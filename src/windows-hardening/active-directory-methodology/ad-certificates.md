# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

### Componenti di un Certificato

- Il **Soggetto** del certificato denota il suo proprietario.
- Una **Chiave Pubblica** è abbinata a una chiave privata per collegare il certificato al suo legittimo proprietario.
- Il **Periodo di Validità**, definito dalle date **NotBefore** e **NotAfter**, segna la durata effettiva del certificato.
- Un **Numero di Serie** unico, fornito dall'Autorità di Certificazione (CA), identifica ciascun certificato.
- L'**Emittente** si riferisce alla CA che ha emesso il certificato.
- **SubjectAlternativeName** consente nomi aggiuntivi per il soggetto, migliorando la flessibilità di identificazione.
- **Basic Constraints** identificano se il certificato è per una CA o un'entità finale e definiscono le restrizioni d'uso.
- **Extended Key Usages (EKUs)** delineano gli scopi specifici del certificato, come la firma del codice o la crittografia delle email, attraverso Identificatori di Oggetto (OIDs).
- L'**Algoritmo di Firma** specifica il metodo per firmare il certificato.
- La **Firma**, creata con la chiave privata dell'emittente, garantisce l'autenticità del certificato.

### Considerazioni Speciali

- I **Subject Alternative Names (SANs)** espandono l'applicabilità di un certificato a più identità, cruciale per i server con più domini. Processi di emissione sicuri sono vitali per evitare rischi di impersonificazione da parte di attaccanti che manipolano la specifica SAN.

### Autorità di Certificazione (CA) in Active Directory (AD)

AD CS riconosce i certificati CA in un bosco AD attraverso contenitori designati, ognuno con ruoli unici:

- Il contenitore **Certification Authorities** contiene certificati CA radice fidati.
- Il contenitore **Enrolment Services** dettaglia le CA aziendali e i loro modelli di certificato.
- L'oggetto **NTAuthCertificates** include certificati CA autorizzati per l'autenticazione AD.
- Il contenitore **AIA (Authority Information Access)** facilita la validazione della catena di certificati con certificati CA intermedi e incrociati.

### Acquisizione del Certificato: Flusso di Richiesta del Certificato Client

1. Il processo di richiesta inizia con i client che trovano una CA aziendale.
2. Viene creato un CSR, contenente una chiave pubblica e altri dettagli, dopo aver generato una coppia di chiavi pubblica-privata.
3. La CA valuta il CSR rispetto ai modelli di certificato disponibili, emettendo il certificato in base ai permessi del modello.
4. Una volta approvato, la CA firma il certificato con la sua chiave privata e lo restituisce al client.

### Modelli di Certificato

Definiti all'interno di AD, questi modelli delineano le impostazioni e i permessi per l'emissione dei certificati, inclusi EKU consentiti e diritti di iscrizione o modifica, critici per gestire l'accesso ai servizi di certificato.

## Iscrizione al Certificato

Il processo di iscrizione per i certificati è avviato da un amministratore che **crea un modello di certificato**, che viene poi **pubblicato** da un'Autorità di Certificazione (CA) aziendale. Questo rende il modello disponibile per l'iscrizione del client, un passaggio ottenuto aggiungendo il nome del modello al campo `certificatetemplates` di un oggetto Active Directory.

Per un client per richiedere un certificato, devono essere concessi **diritti di iscrizione**. Questi diritti sono definiti da descrittori di sicurezza sul modello di certificato e sulla CA aziendale stessa. I permessi devono essere concessi in entrambe le posizioni affinché una richiesta abbia successo.

### Diritti di Iscrizione del Modello

Questi diritti sono specificati attraverso Access Control Entries (ACEs), dettagliando permessi come:

- Diritti di **Certificate-Enrollment** e **Certificate-AutoEnrollment**, ciascuno associato a GUID specifici.
- **ExtendedRights**, che consentono tutti i permessi estesi.
- **FullControl/GenericAll**, fornendo il controllo completo sul modello.

### Diritti di Iscrizione della CA Aziendale

I diritti della CA sono delineati nel suo descrittore di sicurezza, accessibile tramite la console di gestione dell'Autorità di Certificazione. Alcune impostazioni consentono anche a utenti con privilegi bassi l'accesso remoto, il che potrebbe essere una preoccupazione per la sicurezza.

### Controlli Aggiuntivi per l'Emissione

Possono applicarsi controlli specifici, come:

- **Approvazione del Manager**: pone le richieste in uno stato di attesa fino all'approvazione da parte di un manager di certificati.
- **Agenti di Iscrizione e Firme Autorizzate**: specificano il numero di firme richieste su un CSR e i necessari OIDs di Politica Applicativa.

### Metodi per Richiedere Certificati

I certificati possono essere richiesti tramite:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), utilizzando interfacce DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), attraverso pipe nominate o TCP/IP.
3. L'**interfaccia web di iscrizione ai certificati**, con il ruolo di Web Enrollment dell'Autorità di Certificazione installato.
4. Il **Certificate Enrollment Service** (CES), in combinazione con il servizio di Politica di Iscrizione ai Certificati (CEP).
5. Il **Network Device Enrollment Service** (NDES) per dispositivi di rete, utilizzando il Simple Certificate Enrollment Protocol (SCEP).

Gli utenti Windows possono anche richiedere certificati tramite l'interfaccia grafica (`certmgr.msc` o `certlm.msc`) o strumenti da riga di comando (`certreq.exe` o il comando `Get-Certificate` di PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticazione tramite Certificato

Active Directory (AD) supporta l'autenticazione tramite certificato, utilizzando principalmente i protocolli **Kerberos** e **Secure Channel (Schannel)**.

### Processo di Autenticazione Kerberos

Nel processo di autenticazione Kerberos, la richiesta di un utente per un Ticket Granting Ticket (TGT) è firmata utilizzando la **chiave privata** del certificato dell'utente. Questa richiesta subisce diverse validazioni da parte del controller di dominio, inclusi la **validità** del certificato, il **percorso** e lo **stato di revoca**. Le validazioni includono anche la verifica che il certificato provenga da una fonte fidata e la conferma della presenza dell'emittente nel **NTAUTH certificate store**. Validazioni riuscite portano all'emissione di un TGT. L'oggetto **`NTAuthCertificates`** in AD, si trova in:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
è centrale per stabilire fiducia per l'autenticazione dei certificati.

### Autenticazione Secure Channel (Schannel)

Schannel facilita connessioni TLS/SSL sicure, dove durante un handshake, il client presenta un certificato che, se validato con successo, autorizza l'accesso. La mappatura di un certificato a un account AD può coinvolgere la funzione **S4U2Self** di Kerberos o il **Subject Alternative Name (SAN)** del certificato, tra i vari metodi.

### Enumerazione dei Servizi di Certificato AD

I servizi di certificato di AD possono essere enumerati tramite query LDAP, rivelando informazioni sulle **Enterprise Certificate Authorities (CAs)** e le loro configurazioni. Questo è accessibile da qualsiasi utente autenticato nel dominio senza privilegi speciali. Strumenti come **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** sono utilizzati per l'enumerazione e la valutazione delle vulnerabilità negli ambienti AD CS.

I comandi per utilizzare questi strumenti includono:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
---

## Vulnerabilità recenti e aggiornamenti di sicurezza (2022-2025)

| Anno | ID / Nome | Impatto | Punti chiave |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalation dei privilegi* tramite spoofing dei certificati degli account macchina durante PKINIT. | La patch è inclusa negli aggiornamenti di sicurezza del **10 maggio 2022**. Sono stati introdotti controlli di auditing e di mappatura forte tramite **KB5014754**; gli ambienti dovrebbero ora essere in modalità *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Esecuzione di codice remoto* nei ruoli AD CS Web Enrollment (certsrv) e CES. | I PoC pubblici sono limitati, ma i componenti IIS vulnerabili sono spesso esposti internamente. Patch a partire dal **luglio 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Gli utenti a basso privilegio con diritti di registrazione potrebbero sovrascrivere **qualsiasi** EKU o SAN durante la generazione del CSR, emettendo certificati utilizzabili per l'autenticazione del client o la firma del codice, portando a *compromissione del dominio*. | Affrontato negli aggiornamenti di **aprile 2024**. Rimuovere “Supply in the request” dai modelli e limitare i permessi di registrazione.  |

### Cronologia di indurimento di Microsoft (KB5014754)

Microsoft ha introdotto un rollout in tre fasi (Compatibilità → Audit → Enforcement) per spostare l'autenticazione dei certificati Kerberos lontano da mappature implicite deboli. A partire dal **11 febbraio 2025**, i controller di dominio passano automaticamente a **Full Enforcement** se il valore di registro `StrongCertificateBindingEnforcement` non è impostato. Gli amministratori dovrebbero:

1. Applicare patch a tutti i DC e server AD CS (maggio 2022 o successivi).
2. Monitorare l'ID evento 39/41 per mappature deboli durante la fase di *Audit*.
3. Riemettere certificati di autenticazione client con la nuova **estensione SID** o configurare mappature manuali forti prima di febbraio 2025.

---

## Miglioramenti nella rilevazione e nell'indurimento

* Il **Defender for Identity AD CS sensor (2023-2024)** ora presenta valutazioni della postura per ESC1-ESC8/ESC11 e genera avvisi in tempo reale come *“Emissione di certificati per controller di dominio per un non-DC”* (ESC8) e *“Prevenire la registrazione dei certificati con politiche di applicazione arbitrarie”* (ESC15). Assicurati che i sensori siano distribuiti a tutti i server AD CS per beneficiare di queste rilevazioni.
* Disabilita o limita strettamente l'opzione **“Supply in the request”** su tutti i modelli; preferisci valori SAN/EKU definiti esplicitamente.
* Rimuovi **Any Purpose** o **No EKU** dai modelli a meno che non sia assolutamente necessario (affronta scenari ESC2).
* Richiedi **approvazione del manager** o flussi di lavoro dedicati per l'Enrollment Agent per modelli sensibili (ad es., WebServer / CodeSigning).
* Limita l'iscrizione web (`certsrv`) e gli endpoint CES/NDES a reti fidate o dietro autenticazione del certificato client.
* Applica la crittografia dell'iscrizione RPC (`certutil –setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQ`) per mitigare l'ESC11.

---

## Riferimenti

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
