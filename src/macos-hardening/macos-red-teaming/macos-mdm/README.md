# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Per saperne di più sugli MDM di macOS, consulta:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Nozioni di base

### **Panoramica su MDM (Mobile Device Management)**

Il [Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) viene utilizzato per gestire diversi dispositivi degli utenti finali, come smartphone, laptop e tablet. In particolare, per le piattaforme Apple (iOS, macOS, tvOS), comprende un insieme di funzionalità, API e procedure specializzate. Il funzionamento dell’MDM dipende da un server MDM compatibile, disponibile in commercio o open source, che deve supportare il [protocollo MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Punti chiave:

- Controllo centralizzato dei dispositivi.
- Dipendenza da un server MDM conforme al protocollo MDM.
- Il server MDM può inviare vari comandi ai dispositivi, per esempio la cancellazione remota dei dati o l’installazione di configurazioni.

### **Nozioni di base su DEP (Device Enrollment Program)**

Il [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) offerto da Apple semplifica l’integrazione del Mobile Device Management (MDM), consentendo la configurazione zero-touch dei dispositivi iOS, macOS e tvOS. DEP automatizza la procedura di registrazione, permettendo ai dispositivi di essere operativi fin da subito, con un intervento minimo da parte dell’utente o dell’amministratore. Aspetti essenziali:

- Consente ai dispositivi di registrarsi autonomamente presso un server MDM predefinito alla prima attivazione.
- È utile soprattutto per i dispositivi nuovi, ma può essere usato anche per quelli riconfigurati.
- Semplifica la configurazione, rendendo rapidamente i dispositivi pronti per l’uso nell’organizzazione.

### **Considerazioni sulla sicurezza**

È importante notare che, sebbene la semplicità di registrazione offerta da DEP sia vantaggiosa, può anche comportare rischi per la sicurezza. Se non vengono applicate adeguate misure di protezione alla registrazione MDM, gli attaccanti potrebbero sfruttare questa procedura semplificata per registrare il proprio dispositivo sul server MDM dell’organizzazione, facendolo passare per un dispositivo aziendale.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Avviso di sicurezza**: se non sono previste adeguate misure di protezione, la registrazione DEP semplificata potrebbe consentire la registrazione non autorizzata di dispositivi sul server MDM dell’organizzazione.

### Nozioni di base: cos’è SCEP (Simple Certificate Enrolment Protocol)?

- Protocollo relativamente datato, creato prima della diffusione di TLS e HTTPS.
- Offre ai client un metodo standardizzato per inviare una **richiesta di firma del certificato** (CSR) allo scopo di ottenere un certificato. Il client chiede al server di rilasciargli un certificato firmato.

### Cosa sono i Configuration Profiles (detti anche mobileconfigs)?

- Metodo ufficiale di Apple per **impostare e applicare la configurazione di sistema**.
- Formato di file che può contenere più payload.
- Basato su property list (in formato XML).
- «possono essere firmati e crittografati per convalidarne l’origine, garantirne l’integrità e proteggere i contenuti». Nozioni di base — Pagina 70, iOS Security Guide, gennaio 2018.

## Protocolli

### MDM

- Combinazione di APNs (server **Apple**) e API RESTful (server dei **vendor MDM**)
- La **comunicazione** avviene tra un **dispositivo** e un server associato a un **prodotto** di **gestione** dei **dispositivi**
- I **comandi** vengono inviati dall’MDM al dispositivo in **dizionari codificati in plist**
- Tutto avviene su **HTTPS**. I server MDM possono usare il pinning, cosa che di solito fanno.
- Apple rilascia al vendor MDM un **certificato APNs** per l’autenticazione

### DEP

- **3 API**: una per i rivenditori, una per i vendor MDM e una per l’identità del dispositivo (non documentata):
  - La cosiddetta API del [«cloud service» DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). I server MDM la usano per associare profili DEP a dispositivi specifici.
  - L’[API DEP usata dai rivenditori autorizzati Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) per registrare i dispositivi e verificarne lo stato di registrazione e quello delle transazioni.
  - L’API DEP privata non documentata. I dispositivi Apple la usano per richiedere il proprio profilo DEP. Su macOS, il binario `cloudconfigurationd` gestisce la comunicazione tramite questa API.
- Più moderna e basata su **JSON** (anziché plist)
- Apple rilascia al vendor MDM un **token OAuth**

**API «cloud service» DEP**

- RESTful
- Sincronizza i record dei dispositivi da Apple al server MDM
- Sincronizza i «profili DEP» dal server MDM ad Apple (che in seguito li invia al dispositivo)
- Un «profilo» DEP contiene:
  - URL del server del vendor MDM
  - Certificati attendibili aggiuntivi per l’URL del server (pinning facoltativo)
  - Impostazioni aggiuntive (per esempio, quali schermate saltare nell’Assistente configurazione)

## Numero di serie

I dispositivi Apple prodotti dopo il 2010 hanno generalmente numeri di serie **alfanumerici di 12 caratteri**: **le prime tre cifre indicano il luogo di produzione**, le **due successive** indicano **l’anno** e la **settimana** di produzione, le **tre seguenti** forniscono un **identificatore** univoco e le **ultime** **quattro** rappresentano il **numero del modello**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Fasi di registrazione e gestione

1. Creazione del record del dispositivo (rivenditore, Apple): viene creato il record del nuovo dispositivo
2. Assegnazione del record del dispositivo (cliente): il dispositivo viene assegnato a un server MDM
3. Sincronizzazione del record del dispositivo (vendor MDM): l’MDM sincronizza i record dei dispositivi e invia i profili DEP ad Apple
4. Check-in DEP (dispositivo): il dispositivo riceve il proprio profilo DEP
5. Recupero del profilo (dispositivo)
6. Installazione del profilo (dispositivo), con payload MDM, SCEP e CA radice
7. Invio di comandi MDM (dispositivo)

![Numero di serie - Fasi di registrazione e gestione: 7. Invio di comandi MDM (dispositivo)](<../../../images/image (694).png>)

Il file `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` esporta funzioni che possono essere considerate **«fasi» di alto livello** della procedura di registrazione.

### Fase 4: check-in DEP — recupero dell’Activation Record

Questa parte della procedura avviene quando un **utente avvia un Mac per la prima volta** (o dopo una cancellazione completa)

![Fasi di registrazione e gestione - Fase 4: check-in DEP - recupero dell’Activation Record: questa parte della procedura avviene quando un utente avvia un Mac per la prima volta (o dopo una...](<../../../images/image (1044).png>)

oppure quando si esegue `sudo profiles show -type enrollment`

- Determina **se il dispositivo è abilitato per DEP**
- Activation Record è il nome interno del **«profilo» DEP**
- Inizia non appena il dispositivo si connette a Internet
- Gestito da **`CPFetchActivationRecord`**
- Implementato da **`cloudconfigurationd`** tramite XPC. L’**«Assistente configurazione»** (al primo avvio del dispositivo) o il comando **`profiles`** contatta questo demone per recuperare l’activation record.
  - LaunchDaemon (viene sempre eseguito come root)

Per recuperare l’Activation Record, **`MCTeslaConfigurationFetcher`** esegue alcuni passaggi. Questo processo usa una cifratura chiamata **Absinthe**<sup>[[1]](#references)</sup>

1. Recupero del **certificato**
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inizializzazione** dello stato dal certificato (**`NACInit`**)
   1. Usa diversi dati specifici del dispositivo (ad es. **numero di serie tramite `IOKit`**)
3. Recupero della **chiave di sessione**
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Stabilimento della sessione (**`NACKeyEstablishment`**)
5. Invio della richiesta
   1. POST a [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) con i dati `{ "action": "RequestProfileConfiguration", "sn": "" }`
   2. Il payload JSON viene cifrato usando Absinthe (**`NACSign`**)
   3. Tutte le richieste avvengono su HTTPS, usando i certificati radice integrati

![Fasi di registrazione e gestione - Fase 4: check-in DEP - recupero dell’Activation Record: 3. Tutte le richieste avvengono su HTTPS, usando i certificati radice integrati](<../../../images/image (566) (1).png>)

La risposta è un dizionario JSON che contiene dati importanti, come:

- **url**: URL dell’host del vendor MDM per il profilo di attivazione
- **anchor-certs**: array di certificati DER usati come trust anchor

### **Fase 5: recupero del profilo**

![Fase 4: check-in DEP - recupero dell’Activation Record - Fase 5: recupero del profilo: Fase 5: recupero del profilo](<../../../images/image (444).png>)

- La richiesta viene inviata all’**URL specificato nel profilo DEP**.
- Se forniti, i **certificati anchor** vengono usati per **valutare l’attendibilità**.
  - Promemoria: la proprietà **anchor_certs** del profilo DEP
- La **richiesta è un semplice file .plist** contenente l’identificazione del dispositivo
  - Esempi: **UDID, versione del sistema operativo**.
- Firmato con CMS e codificato in DER
- Firmato usando il **certificato di identità del dispositivo (da APNS)**
- La **catena di certificati** include un **Apple iPhone Device CA** scaduto

![Fase 4: check-in DEP - recupero dell’Activation Record - Fase 5: recupero del profilo: firmato usando il certificato di identità del dispositivo (da APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Fase 6: installazione del profilo

- Una volta recuperato, il **profilo viene archiviato nel sistema**
- Questa fase inizia automaticamente (se ci si trova nell’**Assistente configurazione**)
- Gestita da **`CPInstallActivationProfile`**
- Implementata da mdmclient tramite XPC
  - LaunchDaemon (come root) o LaunchAgent (come utente), a seconda del contesto
- I Configuration Profile contengono più payload da installare
- Il framework usa un’architettura basata su plugin per installare i profili
- Ogni tipo di payload è associato a un plugin
  - Può essere XPC (nel framework) o Cocoa classico (in ManagedClient.app)
- Esempio:
  - I payload dei certificati usano CertificateService.xpc

In genere, il **profilo di attivazione** fornito da un vendor MDM **include i seguenti payload**:

- `com.apple.mdm`: per **registrare** il dispositivo nell’MDM
- `com.apple.security.scep`: per fornire in modo sicuro al dispositivo un **certificato client**.
- `com.apple.security.pem`: per **installare i certificati CA attendibili** nel Portachiavi di sistema del dispositivo.
- L’installazione del payload MDM equivale al **check-in MDM descritto nella documentazione**
- Il payload **contiene proprietà chiave**:
- - URL di check-in MDM (**`CheckInURL`**)
  - URL di polling dei comandi MDM (**`ServerURL`**) e argomento APNs per attivarlo
- Per installare il payload MDM, la richiesta viene inviata a **`CheckInURL`**
- Implementato in **`mdmclient`**
- Il payload MDM può dipendere da altri payload
- Consente di **vincolare le richieste a certificati specifici**:
  - Proprietà: **`CheckInURLPinningCertificateUUIDs`**
  - Proprietà: **`ServerURLPinningCertificateUUIDs`**
  - Fornito tramite payload PEM
- Consente di associare al dispositivo un certificato di identità:
  - Proprietà: IdentityCertificateUUID
  - Fornito tramite payload SCEP

### **Fase 7: ascolto dei comandi MDM**

- Una volta completato il check-in MDM, il vendor può **inviare notifiche push tramite APNs**
- Alla ricezione, vengono gestite da **`mdmclient`**
- Per eseguire il polling dei comandi MDM, la richiesta viene inviata a ServerURL
- Viene usato il payload MDM installato in precedenza:
  - **`ServerURLPinningCertificateUUIDs`** per il pinning della richiesta
  - **`IdentityCertificateUUID`** per il certificato client TLS

## Attacchi

### Registrazione di dispositivi in altre organizzazioni

Un numero di serie assegnato può indicare il percorso di registrazione dell’organizzazione, ma **non** garantisce la registrazione MDM. Prima di restituire il profilo di registrazione, il server può richiedere l’autenticazione dell’utente tramite `configuration_web_url`. Verificate se un percorso di registrazione alternativo omette questo controllo, anziché presumere che ogni numero di serie assegnato possa entrare nel parco dispositivi.<sup>[[3]](#references)</sup>

Per una procedura di registrazione non autorizzata, consultate la pagina collegata qui sotto. Per il controllo MDM e la distribuzione di pacchetti dopo una compromissione, consultate [macOS Red Teaming](../).


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}



## References

- [1] [Un’analisi approfondita dell’MDM di macOS (e di come può essere compromesso)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — «MDM Me Maybe?» (ricerca sulla sicurezza della registrazione DEP/MDM)](https://duo.com/labs/research/mdm-me-maybe)
- [3] [Apple — Autenticazione tramite web view](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
{{#include ../../../banners/hacktricks-training.md}}
