# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Per saperne di più sugli MDM di macOS, consulta:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Nozioni di base

### **Panoramica su MDM (Mobile Device Management)**

Il [Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) viene utilizzato per supervisionare vari dispositivi degli utenti finali, come smartphone, laptop e tablet. In particolare, per le piattaforme Apple (iOS, macOS, tvOS), comprende un insieme di funzionalità, API e pratiche specializzate. Il funzionamento dell'MDM dipende da un server MDM compatibile, disponibile commercialmente o open-source, che deve supportare il [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Punti chiave:

- Controllo centralizzato sui dispositivi.
- Dipendenza da un server MDM conforme al protocollo MDM.
- Possibilità per il server MDM di inviare vari comandi ai dispositivi, come la cancellazione remota dei dati o l'installazione di configurazioni.

### **Nozioni di base sul DEP (Device Enrollment Program)**

Il [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) offerto da Apple semplifica l'integrazione del Mobile Device Management (MDM), consentendo la configurazione zero-touch dei dispositivi iOS, macOS e tvOS. DEP automatizza il processo di registrazione, permettendo ai dispositivi di essere operativi subito dopo l'estrazione dalla confezione, con un intervento minimo da parte dell'utente o dell'amministratore. Gli aspetti essenziali includono:

- Consente ai dispositivi di registrarsi autonomamente presso un server MDM predefinito durante la prima attivazione.
- È principalmente utile per i dispositivi nuovi, ma può essere applicato anche ai dispositivi sottoposti a riconfigurazione.
- Facilita una configurazione semplice, rendendo rapidamente i dispositivi pronti per l'uso aziendale.

### **Considerazioni sulla sicurezza**

È fondamentale notare che la semplicità della registrazione fornita dal DEP, pur essendo vantaggiosa, può comportare anche rischi per la sicurezza. Se durante la registrazione MDM non vengono applicate adeguate misure di protezione, gli attacker potrebbero sfruttare questo processo semplificato per registrare il proprio dispositivo sul server MDM dell'organizzazione, fingendosi un dispositivo aziendale.<sup>[2]</sup>

> [!CAUTION]
> **Avviso di sicurezza**: la registrazione DEP semplificata potrebbe consentire la registrazione non autorizzata di un dispositivo sul server MDM dell'organizzazione se non sono presenti adeguate misure di sicurezza.

### Nozioni di base: cos'è SCEP (Simple Certificate Enrolment Protocol)?

- Un protocollo relativamente vecchio, creato prima che TLS e HTTPS fossero ampiamente diffusi.
- Fornisce ai client un modo standardizzato per inviare una **Certificate Signing Request** (CSR) allo scopo di ottenere un certificato. Il client chiede al server di fornirgli un certificato firmato.

### Cosa sono i Configuration Profiles (noti anche come mobileconfigs)?

- Il metodo ufficiale di Apple per **impostare/applicare la configurazione del sistema.**
- Formato di file che può contenere più payload.
- Basati su property list (in formato XML).
- “can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.” Basics — Page 70, iOS Security Guide, January 2018.

## Protocolli

### MDM

- Combinazione di APNs (**server Apple**) + API RESTful (server del **vendor** **MDM**)
- La **comunicazione** avviene tra un **dispositivo** e un server associato a un **prodotto** di **gestione** dei **dispositivi**
- I **comandi** vengono inviati dall'MDM al dispositivo in **dizionari codificati in plist**
- Il tutto tramite **HTTPS**. I server MDM possono utilizzare (e solitamente utilizzano) il pinning.
- Apple fornisce al vendor MDM un **certificato APNs** per l'autenticazione

### DEP

- **3 API**: 1 per i rivenditori, 1 per i vendor MDM e 1 per l'identità del dispositivo (non documentata):
- La cosiddetta API [DEP "cloud service"](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Viene utilizzata dai server MDM per associare i profili DEP a dispositivi specifici.
- L'[API DEP utilizzata dai rivenditori autorizzati Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) per registrare i dispositivi, verificare lo stato della registrazione e verificare lo stato delle transazioni.
- L'API DEP privata e non documentata. Viene utilizzata dai dispositivi Apple per richiedere il proprio profilo DEP. Su macOS, il binario `cloudconfigurationd` è responsabile della comunicazione tramite questa API.
- Più moderna e basata su **JSON** (rispetto a **plist**)
- Apple fornisce al vendor MDM un **token OAuth**

**API DEP "cloud service"**

- RESTful
- sincronizza i record dei dispositivi da Apple al server MDM
- sincronizza i “profili DEP” dal server MDM ad Apple (successivamente consegnati da Apple al dispositivo)
- Un “profilo” DEP contiene:
- URL del server del vendor MDM
- Certificati trusted aggiuntivi per l'URL del server (pinning facoltativo)
- Impostazioni aggiuntive (ad esempio, quali schermate saltare in Setup Assistant)

## Numero di serie

I dispositivi Apple prodotti dopo il 2010 hanno generalmente numeri di serie **alfanumerici di 12 caratteri**, in cui le **prime tre cifre rappresentano il luogo di produzione**, le **due successive** indicano l'**anno** e la **settimana** di produzione, le **tre cifre seguenti** forniscono un **identificatore** **univoco** e le **ultime** quattro cifre rappresentano il **numero del modello**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Fasi di registrazione e gestione

1. Creazione del record del dispositivo (Rivenditore, Apple): viene creato il record del nuovo dispositivo
2. Assegnazione del record del dispositivo (Cliente): il dispositivo viene assegnato a un server MDM
3. Sincronizzazione del record del dispositivo (vendor MDM): l'MDM sincronizza i record dei dispositivi e invia i profili DEP ad Apple
4. Check-in DEP (Dispositivo): il dispositivo riceve il proprio profilo DEP
5. Recupero del profilo (Dispositivo)
6. Installazione del profilo (Dispositivo), inclusi i payload MDM, SCEP e root CA
7. Emissione dei comandi MDM (Dispositivo)

![Numero di serie - Fasi di registrazione e gestione: 7. Emissione dei comandi MDM (Dispositivo)](<../../../images/image (694).png>)

Il file `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` esporta funzioni che possono essere considerate **"fasi" di alto livello** del processo di registrazione.

### Fase 4: check-in DEP - Ottenimento dell'Activation Record

Questa parte del processo avviene quando un **utente avvia un Mac per la prima volta** (o dopo una cancellazione completa)

![Fasi di registrazione e gestione - Fase 4: check-in DEP - Ottenimento dell'Activation Record: questa parte del processo avviene quando un utente avvia un Mac per la prima volta (o dopo una...](<../../../images/image (1044).png>)

oppure quando si esegue `sudo profiles show -type enrollment`

- Determina **se il dispositivo è abilitato per DEP**
- Activation Record è il nome interno del **“profilo” DEP**
- Inizia non appena il dispositivo si connette a Internet
- Gestito da **`CPFetchActivationRecord`**
- Implementato da **`cloudconfigurationd`** tramite XPC. **"Setup Assistant**" (quando il dispositivo viene avviato per la prima volta) oppure il comando **`profiles`** contatterà questo daemon per recuperare l'activation record.
- LaunchDaemon (viene sempre eseguito come root)

Per ottenere l'Activation Record vengono eseguiti alcuni passaggi tramite **`MCTeslaConfigurationFetcher`**. Questo processo utilizza una cifratura chiamata **Absinthe**<sup>[1]</sup>

1. Recupera il **certificato**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inizializza** lo stato dal certificato (**`NACInit`**)
1. Utilizza vari dati specifici del dispositivo (ad esempio il **numero di serie tramite `IOKit`**)
3. Recupera la **chiave di sessione**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Stabilisce la sessione (**`NACKeyEstablishment`**)
5. Esegue la richiesta
1. POST a [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) inviando i dati `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Il payload JSON viene cifrato usando Absinthe (**`NACSign`**)
3. Tutte le richieste avvengono tramite HTTPs, utilizzando i certificati root integrati

![Fasi di registrazione e gestione - Fase 4: check-in DEP - Ottenimento dell'Activation Record: 3. Tutte le richieste avvengono tramite HTTPs, utilizzando i certificati root integrati](<../../../images/image (566) (1).png>)

La risposta è un dizionario JSON con alcuni dati importanti, come:

- **url**: URL dell'host del vendor MDM per il profilo di attivazione
- **anchor-certs**: array di certificati DER utilizzati come anchor trusted

### **Fase 5: recupero del profilo**

![Fase 4: check-in DEP - Ottenimento dell'Activation Record - Fase 5: recupero del profilo: Fase 5: recupero del profilo](<../../../images/image (444).png>)

- La richiesta viene inviata all'**url fornito nel profilo DEP**.
- I **certificati anchor** vengono utilizzati per **valutare l'attendibilità** se forniti.
- Promemoria: la proprietà **anchor_certs** del profilo DEP
- La **richiesta è un semplice .plist** contenente l'identificazione del dispositivo
- Esempi: **UDID, versione del sistema operativo**.
- Firmato tramite CMS, codificato in DER
- Firmato utilizzando il **certificato di identità del dispositivo (da APNS)**
- La **catena di certificati** include il certificato **Apple iPhone Device CA** scaduto

![Fase 4: check-in DEP - Ottenimento dell'Activation Record - Fase 5: recupero del profilo: firmato utilizzando il certificato di identità del dispositivo (da APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Fase 6: installazione del profilo

- Una volta recuperato, il **profilo viene memorizzato nel sistema**
- Questa fase inizia automaticamente (se ci si trova in **Setup Assistant**)
- Gestita da **`CPInstallActivationProfile`**
- Implementata da mdmclient tramite XPC
- LaunchDaemon (come root) o LaunchAgent (come utente), a seconda del contesto
- I profili di configurazione hanno più payload da installare
- Il framework utilizza un'architettura basata su plugin per installare i profili
- Ogni tipo di payload è associato a un plugin
- Può essere XPC (nel framework) o Cocoa classico (in ManagedClient.app)
- Esempio:
- I payload dei certificati utilizzano CertificateService.xpc

In genere, il **profilo di attivazione** fornito da un vendor MDM **includerà i seguenti payload**:

- `com.apple.mdm`: per **registrare** il dispositivo nell'MDM
- `com.apple.security.scep`: per fornire in modo sicuro un **certificato client** al dispositivo.
- `com.apple.security.pem`: per **installare certificati CA trusted** nel System Keychain del dispositivo.
- Installazione del payload MDM equivalente al **check-in MDM nella documentazione**
- Il payload **contiene proprietà chiave**:
- - URL di check-in MDM (**`CheckInURL`**)
- URL di polling dei comandi MDM (**`ServerURL`**) + topic APNs per attivarlo
- Per installare il payload MDM, la richiesta viene inviata a **`CheckInURL`**
- Implementato in **`mdmclient`**
- Il payload MDM può dipendere da altri payload
- Consente di **applicare il pinning delle richieste a certificati specifici**:
- Proprietà: **`CheckInURLPinningCertificateUUIDs`**
- Proprietà: **`ServerURLPinningCertificateUUIDs`**
- Consegnato tramite payload PEM
- Consente di associare al dispositivo un certificato di identità:
- Proprietà: IdentityCertificateUUID
- Consegnato tramite payload SCEP

### **Fase 7: ascolto dei comandi MDM**

- Dopo il completamento del check-in MDM, il vendor può **inviare notifiche push utilizzando APNs**
- Alla ricezione, vengono gestite da **`mdmclient`**
- Per eseguire il polling dei comandi MDM, la richiesta viene inviata a ServerURL
- Utilizza il payload MDM installato in precedenza:
- **`ServerURLPinningCertificateUUIDs`** per applicare il pinning alla richiesta
- **`IdentityCertificateUUID`** per il certificato client TLS

## Attacchi

### Registrazione di dispositivi in altre organizzazioni

Come già commentato, per provare a registrare un dispositivo in un'organizzazione è necessario **solo un numero di serie appartenente a quell'organizzazione**. Una volta registrato il dispositivo, diverse organizzazioni installeranno dati sensibili sul nuovo dispositivo: certificati, applicazioni, password WiFi, configurazioni VPN [e così via](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Pertanto, questo potrebbe rappresentare un punto d'ingresso pericoloso per gli attacker se il processo di registrazione non è adeguatamente protetto:<sup>[2]</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Riferimenti

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
