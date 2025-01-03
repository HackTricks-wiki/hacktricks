# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Per saperne di più sugli MDM di macOS, controlla:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Fondamenti

### **Panoramica di MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) è utilizzato per supervisionare vari dispositivi finali come smartphone, laptop e tablet. In particolare per le piattaforme Apple (iOS, macOS, tvOS), coinvolge un insieme di funzionalità specializzate, API e pratiche. Il funzionamento di MDM si basa su un server MDM compatibile, che è disponibile commercialmente o open-source, e deve supportare il [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). I punti chiave includono:

- Controllo centralizzato sui dispositivi.
- Dipendenza da un server MDM che aderisca al protocollo MDM.
- Capacità del server MDM di inviare vari comandi ai dispositivi, ad esempio, cancellazione remota dei dati o installazione di configurazioni.

### **Fondamenti del DEP (Device Enrollment Program)**

Il [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) offerto da Apple semplifica l'integrazione del Mobile Device Management (MDM) facilitando la configurazione senza contatto per dispositivi iOS, macOS e tvOS. Il DEP automatizza il processo di registrazione, consentendo ai dispositivi di essere operativi subito dopo l'apertura della confezione, con un intervento minimo da parte dell'utente o dell'amministratore. Gli aspetti essenziali includono:

- Consente ai dispositivi di registrarsi autonomamente con un server MDM predefinito al momento dell'attivazione iniziale.
- Principalmente vantaggioso per dispositivi nuovi, ma applicabile anche a dispositivi in fase di riconfigurazione.
- Facilita una configurazione semplice, rendendo i dispositivi pronti per l'uso organizzativo rapidamente.

### **Considerazione sulla Sicurezza**

È fondamentale notare che la facilità di registrazione fornita dal DEP, sebbene vantaggiosa, può anche comportare rischi per la sicurezza. Se le misure protettive non sono adeguatamente applicate per la registrazione MDM, gli attaccanti potrebbero sfruttare questo processo semplificato per registrare il proprio dispositivo sul server MDM dell'organizzazione, spacciandosi per un dispositivo aziendale.

> [!CAUTION]
> **Avviso di Sicurezza**: La registrazione semplificata del DEP potrebbe consentire la registrazione non autorizzata di dispositivi sul server MDM dell'organizzazione se non sono in atto le giuste misure di protezione.

### Fondamenti Cos'è SCEP (Simple Certificate Enrollment Protocol)?

- Un protocollo relativamente vecchio, creato prima che TLS e HTTPS fossero diffusi.
- Fornisce ai client un modo standardizzato per inviare una **Certificate Signing Request** (CSR) al fine di ottenere un certificato. Il client chiederà al server di fornirgli un certificato firmato.

### Cosa sono i Profili di Configurazione (aka mobileconfigs)?

- Il modo ufficiale di Apple per **impostare/applicare la configurazione di sistema.**
- Formato di file che può contenere più payload.
- Basato su elenchi di proprietà (il tipo XML).
- “possono essere firmati e crittografati per convalidare la loro origine, garantire la loro integrità e proteggere i loro contenuti.” Fondamenti — Pagina 70, iOS Security Guide, gennaio 2018.

## Protocolli

### MDM

- Combinazione di APNs (**server Apple**) + API RESTful (**server fornitori MDM**)
- **La comunicazione** avviene tra un **dispositivo** e un server associato a un **prodotto di gestione dei dispositivi**
- **Comandi** inviati dal MDM al dispositivo in **dizionari codificati plist**
- Tutto su **HTTPS**. I server MDM possono essere (e di solito sono) pinati.
- Apple concede al fornitore MDM un **certificato APNs** per l'autenticazione

### DEP

- **3 API**: 1 per rivenditori, 1 per fornitori MDM, 1 per identità del dispositivo (non documentata):
- La cosiddetta [API "cloud service" DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Questa è utilizzata dai server MDM per associare i profili DEP a dispositivi specifici.
- L'[API DEP utilizzata dai Rivenditori Autorizzati Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) per registrare dispositivi, controllare lo stato di registrazione e controllare lo stato delle transazioni.
- L'API privata DEP non documentata. Questa è utilizzata dai dispositivi Apple per richiedere il proprio profilo DEP. Su macOS, il binario `cloudconfigurationd` è responsabile della comunicazione su questa API.
- Più moderna e basata su **JSON** (rispetto a plist)
- Apple concede un **token OAuth** al fornitore MDM

**API "cloud service" DEP**

- RESTful
- sincronizza i record dei dispositivi da Apple al server MDM
- sincronizza i “profili DEP” da Apple al server MDM (forniti da Apple al dispositivo in seguito)
- Un “profilo” DEP contiene:
- URL del server del fornitore MDM
- Certificati aggiuntivi di fiducia per l'URL del server (pinning opzionale)
- Impostazioni extra (ad es. quali schermate saltare nell'Assistente Configurazione)

## Numero di Serie

I dispositivi Apple prodotti dopo il 2010 hanno generalmente numeri di serie **alfanumerici di 12 caratteri**, con le **prime tre cifre che rappresentano il luogo di produzione**, le successive **due** che indicano l'**anno** e la **settimana** di produzione, le successive **tre** cifre forniscono un **identificatore unico**, e le **ultime** **quattro** cifre rappresentano il **numero di modello**.

{{#ref}}
macos-serial-number.md
{{#endref}}

## Passaggi per la registrazione e la gestione

1. Creazione del record del dispositivo (Rivenditore, Apple): Viene creato il record per il nuovo dispositivo
2. Assegnazione del record del dispositivo (Cliente): Il dispositivo viene assegnato a un server MDM
3. Sincronizzazione del record del dispositivo (fornitore MDM): MDM sincronizza i record dei dispositivi e invia i profili DEP ad Apple
4. Check-in DEP (Dispositivo): Il dispositivo ottiene il suo profilo DEP
5. Recupero del profilo (Dispositivo)
6. Installazione del profilo (Dispositivo) a. incl. payload MDM, SCEP e root CA
7. Emissione del comando MDM (Dispositivo)

![](<../../../images/image (694).png>)

Il file `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` esporta funzioni che possono essere considerate **"passaggi" di alto livello** del processo di registrazione.

### Passo 4: Check-in DEP - Ottenere il Record di Attivazione

Questa parte del processo si verifica quando un **utente avvia un Mac per la prima volta** (o dopo un ripristino completo)

![](<../../../images/image (1044).png>)

o quando si esegue `sudo profiles show -type enrollment`

- Determina **se il dispositivo è abilitato per DEP**
- Il Record di Attivazione è il nome interno per il **"profilo" DEP**
- Inizia non appena il dispositivo è connesso a Internet
- Guidato da **`CPFetchActivationRecord`**
- Implementato da **`cloudconfigurationd`** tramite XPC. L'**"Assistente Configurazione"** (quando il dispositivo viene avviato per la prima volta) o il comando **`profiles`** contatteranno questo demone per recuperare il record di attivazione.
- LaunchDaemon (gira sempre come root)

Segue alcuni passaggi per ottenere il Record di Attivazione eseguiti da **`MCTeslaConfigurationFetcher`**. Questo processo utilizza una crittografia chiamata **Absinthe**

1. Recupera **certificato**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inizializza** lo stato dal certificato (**`NACInit`**)
1. Utilizza vari dati specifici del dispositivo (ad es. **Numero di Serie tramite `IOKit`**)
3. Recupera **chiave di sessione**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Stabilisce la sessione (**`NACKeyEstablishment`**)
5. Effettua la richiesta
1. POST a [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) inviando i dati `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Il payload JSON è crittografato utilizzando Absinthe (**`NACSign`**)
3. Tutte le richieste su HTTPs, vengono utilizzati certificati root integrati

![](<../../../images/image (566) (1).png>)

La risposta è un dizionario JSON con alcuni dati importanti come:

- **url**: URL dell'host del fornitore MDM per il profilo di attivazione
- **anchor-certs**: Array di certificati DER utilizzati come ancore fidate

### **Passo 5: Recupero del Profilo**

![](<../../../images/image (444).png>)

- Richiesta inviata all'**url fornito nel profilo DEP**.
- **Certificati ancorati** sono utilizzati per **valutare la fiducia** se forniti.
- Promemoria: la proprietà **anchor_certs** del profilo DEP
- **La richiesta è un semplice .plist** con identificazione del dispositivo
- Esempi: **UDID, versione OS**.
- Firmato CMS, codificato DER
- Firmato utilizzando il **certificato di identità del dispositivo (da APNS)**
- La **catena di certificati** include un **Apple iPhone Device CA** scaduto

![](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Passo 6: Installazione del Profilo

- Una volta recuperato, **il profilo viene memorizzato nel sistema**
- Questo passaggio inizia automaticamente (se nell'**assistente di configurazione**)
- Guidato da **`CPInstallActivationProfile`**
- Implementato da mdmclient tramite XPC
- LaunchDaemon (come root) o LaunchAgent (come utente), a seconda del contesto
- I profili di configurazione hanno più payload da installare
- Il framework ha un'architettura basata su plugin per l'installazione dei profili
- Ogni tipo di payload è associato a un plugin
- Può essere XPC (nel framework) o Cocoa classico (in ManagedClient.app)
- Esempio:
- I payload dei certificati utilizzano CertificateService.xpc

Tipicamente, il **profilo di attivazione** fornito da un fornitore MDM includerà i seguenti payload:

- `com.apple.mdm`: per **registrare** il dispositivo in MDM
- `com.apple.security.scep`: per fornire in modo sicuro un **certificato client** al dispositivo.
- `com.apple.security.pem`: per **installare certificati CA fidati** nel portachiavi di sistema del dispositivo.
- L'installazione del payload MDM è equivalente al **check-in MDM nella documentazione**
- Il payload **contiene proprietà chiave**:
- - URL di Check-In MDM (**`CheckInURL`**)
- URL di polling dei comandi MDM (**`ServerURL`**) + argomento APNs per attivarlo
- Per installare il payload MDM, viene inviata una richiesta a **`CheckInURL`**
- Implementato in **`mdmclient`**
- Il payload MDM può dipendere da altri payload
- Consente **richieste di essere pinati a certificati specifici**:
- Proprietà: **`CheckInURLPinningCertificateUUIDs`**
- Proprietà: **`ServerURLPinningCertificateUUIDs`**
- Fornito tramite payload PEM
- Consente al dispositivo di essere attribuito con un certificato di identità:
- Proprietà: IdentityCertificateUUID
- Fornito tramite payload SCEP

### **Passo 7: Ascoltare i comandi MDM**

- Dopo che il check-in MDM è completo, il fornitore può **emissione notifiche push utilizzando APNs**
- Al ricevimento, gestito da **`mdmclient`**
- Per interrogare i comandi MDM, viene inviata una richiesta a ServerURL
- Utilizza il payload MDM precedentemente installato:
- **`ServerURLPinningCertificateUUIDs`** per la richiesta di pinning
- **`IdentityCertificateUUID`** per il certificato client TLS

## Attacchi

### Registrazione di Dispositivi in Altre Organizzazioni

Come commentato in precedenza, per cercare di registrare un dispositivo in un'organizzazione **è necessario solo un Numero di Serie appartenente a quell'Organizzazione**. Una volta che il dispositivo è registrato, diverse organizzazioni installeranno dati sensibili sul nuovo dispositivo: certificati, applicazioni, password WiFi, configurazioni VPN [e così via](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Pertanto, questo potrebbe essere un pericoloso punto di ingresso per gli attaccanti se il processo di registrazione non è correttamente protetto:

{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
