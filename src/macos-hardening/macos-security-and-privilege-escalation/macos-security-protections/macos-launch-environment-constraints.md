# Vincoli di avvio/ambiente di macOS e Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

I vincoli di avvio in macOS sono stati introdotti per migliorare la sicurezza **regolando come, da chi e da dove può essere avviato un processo**. Introdotti in macOS Ventura, forniscono un framework che suddivide **ogni binario di sistema in categorie di vincoli distinte**, definite all’interno della **trust cache**, un elenco contenente i binari di sistema e i rispettivi hash. Questi vincoli si applicano a ogni binario eseguibile del sistema e comportano un insieme di **regole** che definiscono i requisiti per **avviare un particolare binario**. Le regole comprendono vincoli self, che un binario deve soddisfare, vincoli parent, che devono essere soddisfatti dal processo padre, e vincoli responsible, a cui devono attenersi altre entità rilevanti.<sup>[[1]](#references)[[4]](#references)</sup>

A partire da macOS Sonoma, il meccanismo si estende alle app di terze parti tramite gli **Environment Constraints**, consentendo agli sviluppatori di proteggere le proprie app specificando un **insieme di chiavi e valori per i vincoli di ambiente**.<sup>[[5]](#references)</sup>

I **vincoli di ambiente di avvio e di caricamento delle librerie** si definiscono in dizionari di vincoli, che si possono salvare in file property list di **`launchd`** oppure in file **property list separati** da usare nella firma del codice.<sup>[[5]](#references)</sup>

Esistono 4 tipi di vincoli:

- **Self Constraints**: vincoli applicati al binario **in esecuzione**.
- **Parent Process**: vincoli applicati al **processo padre** (ad esempio, **`launchd`** che esegue un servizio XP)
- **Responsible Constraints**: vincoli applicati al **processo che chiama il servizio** in una comunicazione XPC
- **Library load constraints**: usate per descrivere in modo selettivo il codice che può essere caricato

Quando un processo prova ad avviarne un altro — chiamando `execve(_:_:_:)` o `posix_spawn(_:_:_:_:_:_:)` — il sistema operativo verifica che il file **eseguibile** **soddisfi** il proprio **vincolo self**. Verifica inoltre che l’eseguibile del processo **padre** **soddisfi il vincolo parent** dell’eseguibile e che l’eseguibile del processo **responsible** **soddisfi il vincolo responsible dell’eseguibile**. Se uno qualsiasi di questi vincoli di avvio non viene soddisfatto, il sistema operativo non esegue il programma.

Se, durante il caricamento di una libreria, una parte qualsiasi del **vincolo della libreria non è soddisfatta**, il processo **non carica** la libreria.

## Categorie LC

Una LC è composta da **fatti** e **operazioni logiche** (and, or...) che combinano i fatti.

I[ **fatti utilizzabili da una LC sono documentati**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Ad esempio:

- is-init-proc: valore booleano che indica se l’eseguibile deve essere il processo di inizializzazione del sistema operativo (`launchd`).
- is-sip-protected: valore booleano che indica se l’eseguibile deve essere un file protetto da System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` valore booleano che indica se il sistema operativo ha caricato l’eseguibile da un volume APFS autorizzato e autenticato.
- `on-authorized-authapfs-volume`: valore booleano che indica se il sistema operativo ha caricato l’eseguibile da un volume APFS autorizzato e autenticato.
  - Volume Cryptexes
- `on-system-volume:` valore booleano che indica se il sistema operativo ha caricato l’eseguibile dal volume di sistema attualmente avviato.
  - All’interno di /System...
- ...

Quando viene firmato un binario Apple, **gli viene assegnata una categoria LC** all’interno della **trust cache**.

- Le **categorie LC di iOS 16** sono state [**decodificate e documentate qui**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Le attuali **categorie LC (macOS 14** - Somona) sono state decodificate e le relative [**descrizioni sono disponibili qui**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Ad esempio, la categoria 1 è:<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: Deve trovarsi nel volume System o Cryptexes.
- `launch-type == 1`: Deve essere un servizio di sistema (plist in LaunchDaemons).
- `validation-category == 1`: Un eseguibile del sistema operativo.
- `is-init-proc`: Launchd

### Reverse engineering delle categorie LC

Puoi trovare maggiori informazioni [**qui**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), ma in breve, sono definite in **AMFI (AppleMobileFileIntegrity)**, quindi devi scaricare il Kernel Development Kit per ottenere il **KEXT**. I simboli che iniziano con **`kConstraintCategory`** sono quelli **interessanti**. Estraendoli, otterrai un flusso codificato in DER (ASN.1), che dovrai decodificare con [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) oppure con la libreria python-asn1 e il relativo script `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), che restituirà una stringa più comprensibile.<sup>[[3]](#references)[[8]](#references)</sup>

## Vincoli dell'ambiente

Questi sono i Launch Constraints configurati nelle **applicazioni di terze parti**. Lo sviluppatore può selezionare i **fatti** e gli **operatori logici da usare** nella propria applicazione per limitarne l'accesso.

È possibile enumerare i vincoli dell'ambiente di un'applicazione con:

```bash
codesign -d -vvvv app.app
```

## Cache di attendibilità

In **macOS** ci sono alcune cache di attendibilità:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

E in iOS sembra trovarsi in **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Su macOS in esecuzione sui dispositivi Apple Silicon, se un binario firmato da Apple non è nella trust cache, AMFI ne rifiuterà il caricamento.

### Enumerazione delle trust cache

I file delle trust cache precedenti sono nel formato **IMG4** e **IM4P**; IM4P è la sezione payload di un formato IMG4.

Puoi usare [**pyimg4**](https://github.com/m1stadev/PyIMG4) per estrarre il payload dei database:

```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```

(Un'altra opzione potrebbe essere usare lo strumento [**img4tool**](https://github.com/tihmstar/img4tool), che funziona anche su M1, nonostante la release sia vecchia e destinata a x86_64, se lo installi nelle posizioni corrette).

Ora puoi usare lo strumento [**trustcache**](https://github.com/CRKatri/trustcache) per ottenere le informazioni in un formato leggibile:

```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```

La trust cache segue la struttura seguente, quindi la **categoria LC è la 4ª colonna**

```c
struct trust_cache_entry2 {
	uint8_t cdhash[CS_CDHASH_LEN];
	uint8_t hash_type;
	uint8_t flags;
	uint8_t constraintCategory;
	uint8_t reserved0;
} __attribute__((__packed__));
```

Quindi, potresti usare uno script come [**questo**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) per estrarre i dati.

Da questi dati puoi individuare le app con un **valore dei vincoli di avvio pari a `0`**, ovvero quelle che non sono soggette a vincoli (consulta [**qui**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) la descrizione di ciascun valore).<sup>[[6]](#references)</sup>

## Mitigazioni degli attacchi

I vincoli di avvio avrebbero mitigato diversi vecchi attacchi **assicurando che il processo non venga eseguito in condizioni impreviste**: per esempio, da posizioni inattese o avviato da un processo padre non previsto (se dovrebbe essere avviato solo da launchd).

Inoltre, i vincoli di avvio **mitigano anche gli attacchi di downgrade**.

Tuttavia, **non mitigano gli abusi comuni di XPC**, le iniezioni di codice **Electron** o le **iniezioni di dylib** in assenza di library validation (a meno che non siano noti i team ID autorizzati a caricare le librerie).<sup>[[3]](#references)</sup>

### Protezione dei daemon XPC

Nella release Sonoma, un aspetto degno di nota è la configurazione della **responsabilità** del servizio XPC del daemon. Il servizio XPC è responsabile di sé stesso, invece che lo sia il client che si connette. Questa configurazione è documentata nel report di feedback FB13206884. Potrebbe sembrare un difetto, poiché consente alcune interazioni con il servizio XPC:

- **Avvio del servizio XPC**: anche se considerata un bug, questa configurazione non consente di avviare il servizio XPC tramite codice dell'attaccante.
- **Connessione a un servizio attivo**: se il servizio XPC è già in esecuzione (magari avviato dalla sua applicazione originale), non ci sono ostacoli alla connessione.

Applicare vincoli al servizio XPC potrebbe essere utile per **ridurre la finestra temporale di potenziali attacchi**, ma non risolve il problema principale. Per garantire la sicurezza del servizio XPC è fondamentale **convalidare efficacemente il client che si connette**. Questo resta l'unico metodo per rafforzare la sicurezza del servizio. Vale inoltre la pena notare che la configurazione della responsabilità menzionata è attualmente operativa, il che potrebbe non corrispondere al design previsto.<sup>[[3]](#references)</sup>

### Protezione di Electron

Anche se è necessario che l'applicazione venga **aperta da LaunchService** (nei vincoli del processo padre), è possibile farlo usando **`open`** (che può impostare variabili d'ambiente) oppure l'**API Launch Services** (che consente di specificare variabili d'ambiente).<sup>[[3]](#references)</sup>

Per informazioni sul meccanismo MACF generale alla base degli attributi di spawn specifici delle policy, consulta [MACF policy-specific spawn attributes](macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input).

### CVE-2025-43253 - Sovrascrittura dei vincoli integrati al momento dello spawn

I vincoli di avvio (ufficialmente **lightweight code requirements**, *LWCR*) sono applicati dalla **policy MAC di AMFI**. `posix_spawn` consente a un chiamante di passare un blob arbitrario a una policy MAC tramite **`posix_spawnattr_setmacpolicyinfo_np()`**, e AMFI accettava tramite questo percorso un dizionario LWCR fornito dal chiamante. Il bug consisteva nel fatto che i **vincoli forniti dall'attaccante sostituivano quelli integrati nel binario**, invece di essere verificati in aggiunta a essi:

- Creare un dizionario di vincoli di avvio minimo (anche vuoto).
- Impostare la **categoria di vincolo su `127`**, un valore che AMFI consente negli attributi di spawn ma **non applica**: registra soltanto `Launch Constraint Violation (not enforcing)` invece di bloccare l'esecuzione.
- Passarlo tramite gli attributi di spawn: il processo viene avviato in un contesto che i suoi vincoli effettivi, propri o del processo padre, avrebbero vietato.

Dopo la correzione, vengono convalidati **sia** i vincoli integrati sia quelli forniti, quindi il dizionario fornito non può più indebolire quelli integrati.<sup>[[2]](#references)</sup>

> [!TIP]
> Questo è il tipo di situazione da cercare durante la verifica dell'applicazione dei vincoli: un'API che consente a input non attendibili di *fornire* una policy è spesso interessante quando il motore delle policy tratta il valore fornito come una sostituzione anziché come un requisito aggiuntivo.



## References

- [1] [Objective by the Sea #OBTS v6.0, giorno 2 (diretta)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: aggirare i vincoli di avvio su macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Approfondimento sui vincoli di avvio e dell'ambiente - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Perché un'app di sistema o uno strumento da riga di comando non si avvia? Vincoli di avvio e cache di attendibilità - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Proteggi la tua app Mac con i vincoli dell'ambiente - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Descrizione dei vincoli di avvio introdotti in iOS 16 (gist di LinusHenze)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [Vincoli di avvio di macOS Sonoma (14) (gist di theevilbit)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Oltre i classici LaunchAgents: approfondimento](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
