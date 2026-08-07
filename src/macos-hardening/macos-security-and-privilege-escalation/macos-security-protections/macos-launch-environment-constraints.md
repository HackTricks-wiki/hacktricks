# Vincoli di avvio/ambiente di macOS e Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

I launch constraints in macOS sono stati introdotti per migliorare la sicurezza **regolando come, da chi e da dove può essere avviato un processo**. Introdotti in macOS Ventura, forniscono un framework che categorizza **ogni binary di sistema in categorie di constraint distinte**, definite all'interno della **trust cache**, un elenco contenente i binary di sistema e i rispettivi hash. Questi constraint si estendono a ogni binary eseguibile presente nel sistema e comprendono un insieme di **regole** che definiscono i requisiti per **avviare uno specifico binary**. Le regole includono self constraints che un binary deve soddisfare, parent constraints che il processo padre deve rispettare e responsible constraints che devono essere rispettati da altre entità rilevanti.<sup>[[1]](#references)[[4]](#references)</sup>

Il meccanismo si estende alle app di terze parti tramite gli **Environment Constraints**, a partire da macOS Sonoma, consentendo agli sviluppatori di proteggere le proprie app specificando un **insieme di chiavi e valori per gli environment constraints**.<sup>[[5]](#references)</sup>

Definisci i **launch environment e library constraints** in constraint dictionaries che puoi salvare nei **file property list di `launchd`**, oppure in file **property list separati** utilizzati nel code signing.<sup>[[5]](#references)</sup>

Esistono 4 tipi di constraint:

- **Self Constraints**: constraint applicati al binary **in esecuzione**.
- **Parent Process**: constraint applicati al **processo padre** del processo (ad esempio **`launchd`** che esegue un servizio XP)
- **Responsible Constraints**: constraint applicati al **processo che chiama il servizio** in una comunicazione XPC
- **Library load constraints**: utilizza i library load constraints per descrivere selettivamente il codice che può essere caricato

Quando un processo tenta di avviare un altro processo, chiamando `execve(_:_:_:)` o `posix_spawn(_:_:_:_:_:_:)`, il sistema operativo verifica che il file **eseguibile** **soddisfi il proprio self constraint**. Verifica inoltre che l'eseguibile del **processo** **padre** soddisfi il **parent constraint** dell'eseguibile e che l'eseguibile del **processo** **responsible** soddisfi il **responsible process constraint** dell'eseguibile. Se uno qualsiasi di questi launch constraints non viene soddisfatto, il sistema operativo non esegue il programma.

Se, durante il caricamento di una library, una qualsiasi parte del **library constraint non è vera**, il processo **non carica** la library.

## Categorie LC

Una LC è composta da **facts** e **operazioni logiche** (and, or...) che combinano le facts.

Le[ **facts che una LC può utilizzare sono documentate**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Ad esempio:

- is-init-proc: valore Boolean che indica se l'eseguibile deve essere il processo di inizializzazione del sistema operativo (`launchd`).
- is-sip-protected: valore Boolean che indica se l'eseguibile deve essere un file protetto da System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` valore Boolean che indica se il sistema operativo ha caricato l'eseguibile da un volume APFS autorizzato e autenticato.
- `on-authorized-authapfs-volume`: valore Boolean che indica se il sistema operativo ha caricato l'eseguibile da un volume APFS autorizzato e autenticato.
- Cryptexes volume
- `on-system-volume:` valore Boolean che indica se il sistema operativo ha caricato l'eseguibile dal volume di sistema attualmente utilizzato per il boot.
- All'interno di /System...
- ...

Quando un binary Apple viene firmato, **lo assegna a una categoria LC** all'interno della **trust cache**.

- Le **categorie LC di iOS 16** sono state [**reversed e documentate qui**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Le attuali **categorie LC (macOS 14** - Sonoma) sono state sottoposte a reverse engineering e le loro [**descrizioni sono disponibili qui**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Ad esempio, la Category 1 è:<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Deve trovarsi nel volume System o Cryptexes.
- `launch-type == 1`: Deve essere un system service (plist in LaunchDaemons).
- `validation-category == 1`: Un eseguibile del sistema operativo.
- `is-init-proc`: Launchd

### Reversing LC Categories

Puoi trovare maggiori informazioni [**qui**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), ma in pratica sono definite in **AMFI (AppleMobileFileIntegrity)**, quindi devi scaricare il Kernel Development Kit per ottenere la **KEXT**. I simboli che iniziano con **`kConstraintCategory`** sono quelli **interessanti**. Estraendoli otterrai uno stream codificato in DER (ASN.1), che dovrai decodificare con [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) oppure con la libreria python-asn1 e il relativo script `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), che restituirà una stringa più comprensibile.<sup>[[3]](#references)[[8]](#references)</sup>

## Environment Constraints

Questi sono i Launch Constraints configurati nelle **applicazioni di terze parti**. Lo sviluppatore può selezionare i **facts** e gli **operatori logici** da utilizzare nella propria applicazione per limitarne l'accesso.

È possibile enumerare gli Environment Constraints di un'applicazione con:
```bash
codesign -d -vvvv app.app
```
## Cache di trust

In **macOS** sono presenti alcune cache di trust:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

In iOS sembra trovarsi in **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Su macOS in esecuzione su dispositivi Apple Silicon, se un binary firmato da Apple non è presente nella trust cache, AMFI rifiuterà di caricarlo.

### Enumerazione delle cache di trust

I precedenti file delle trust cache sono nel formato **IMG4** e **IM4P**, dove IM4P è la sezione payload di un formato IMG4.

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
(Un'altra opzione potrebbe essere utilizzare lo strumento [**img4tool**](https://github.com/tihmstar/img4tool), che verrà eseguito anche su M1, anche se la release è vecchia, e su x86_64 se lo installi nelle posizioni appropriate).

Ora puoi utilizzare lo strumento [**trustcache**](https://github.com/CRKatri/trustcache) per ottenere le informazioni in un formato leggibile:
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

Da questi dati puoi controllare le App con un **launch constraints value pari a `0`**, ovvero quelle che non sono soggette a constraint ([**controlla qui**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) per vedere il significato di ciascun valore).<sup>[[6]](#references)</sup>

## Mitigazioni degli attacchi

Le Launch Constraints avrebbero mitigato diversi vecchi attacchi **assicurandosi che il processo non venisse eseguito in condizioni impreviste:** ad esempio da percorsi imprevisti o venendo invocato da un processo padre imprevisto (se solo launchd dovrebbe avviarlo).

Inoltre, le Launch Constraints **mitigano anche gli attacchi di downgrade.**

Tuttavia, **non mitigano i comuni abusi di XPC**, le code injection di **Electron** o le **dylib injection** senza library validation (a meno che non siano noti i team ID autorizzati a caricare le librerie).<sup>[[3]](#references)</sup>

### Protezione dei daemon XPC

Nella release Sonoma, un aspetto degno di nota è la **configurazione della responsabilità** del servizio XPC del daemon. Il servizio XPC è responsabile di se stesso, invece di essere il client connesso a essere responsabile. Questo è documentato nel feedback report FB13206884. Questa configurazione potrebbe sembrare difettosa, poiché consente alcune interazioni con il servizio XPC:

- **Avvio del servizio XPC**: se considerata un bug, questa configurazione non consente di avviare il servizio XPC tramite codice dell'attacker.
- **Connessione a un servizio attivo**: se il servizio XPC è già in esecuzione (possibilmente attivato dalla sua applicazione originale), non ci sono barriere alla connessione.

Sebbene implementare constraint sul servizio XPC possa essere utile per **ridurre la finestra di potenziali attacchi**, non risolve il problema principale. Garantire la sicurezza del servizio XPC richiede fondamentalmente di **validare in modo efficace il client connesso**. Questo resta l'unico metodo per rafforzare la sicurezza del servizio. Inoltre, vale la pena notare che la configurazione della responsabilità menzionata è attualmente operativa, il che potrebbe non essere in linea con il design previsto.<sup>[[3]](#references)</sup>

### Protezione di Electron

Anche se è necessario che l'applicazione debba essere **aperta da LaunchService** (nei parent constraints), ciò può essere ottenuto usando **`open`** (che può impostare variabili d'ambiente) o usando la **Launch Services API** (dove è possibile indicare le variabili d'ambiente).<sup>[[3]](#references)</sup>

### CVE-2025-43253 - Sovrascrittura dei constraint integrati al momento dello spawn

Le launch constraints (ufficialmente **lightweight code requirements**, *LWCR*) sono applicate dalla **AMFI MAC policy**. `posix_spawn` consente a un chiamante di passare un blob arbitrario a una MAC policy tramite **`posix_spawnattr_setmacpolicyinfo_np()`**, e AMFI accettava un dizionario LWCR fornito dal chiamante attraverso quel percorso. Il bug consisteva nel fatto che i **constraint forniti dall'attacker sostituivano quelli integrati nel binario** invece di essere verificati in aggiunta a questi:

- Creare un dizionario di launch constraints minimale (anche vuoto).
- Impostare la **constraint category a `127`**, un valore che AMFI consente negli attributi di spawn ma **non applica**: registra solo `Launch Constraint Violation (not enforcing)` invece di bloccare l'esecuzione.
- Passarlo tramite gli attributi di spawn: il processo viene quindi avviato in un contesto che i suoi real self/parent constraints avrebbero vietato.

Dopo la correzione, vengono validati **sia i constraint integrati sia quelli forniti**, quindi il dizionario fornito non può più indebolire quello integrato.<sup>[[2]](#references)</sup>

> [!TIP]
> Questa è la struttura generale da ricercare durante l'audit dell'applicazione dei constraint: un'API che consente a input non attendibili di *fornire* una policy tende a essere interessante ogni volta che il policy engine tratta il valore fornito come una sostituzione anziché come un requisito aggiuntivo.

## Riferimenti

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Beyond the good ol` LaunchAgents - about it in here](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)

{{#include ../../../banners/hacktricks-training.md}}
