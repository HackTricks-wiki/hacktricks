# Certificati AD

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

### Componenti di un certificato

- Il **Subject** del certificato indica il suo proprietario.
- Una **Public Key** è accoppiata a una chiave privata per collegare il certificato al legittimo proprietario.
- Il **Validity Period**, definito dalle date **NotBefore** e **NotAfter**, delimita la durata di validità del certificato.
- Un **Serial Number** unico, fornito dalla Certificate Authority (CA), identifica ogni certificato.
- L'**Issuer** si riferisce alla CA che ha emesso il certificato.
- **SubjectAlternativeName** permette nomi aggiuntivi per il subject, aumentando la flessibilità d'identificazione.
- **Basic Constraints** identificano se il certificato è per una CA o per un'entità finale e definiscono restrizioni d'uso.
- **Extended Key Usages (EKUs)** delineano gli scopi specifici del certificato, come code signing o cifratura email, tramite Object Identifiers (OIDs).
- Il **Signature Algorithm** specifica il metodo per firmare il certificato.
- La **Signature**, creata con la chiave privata dell'issuer, garantisce l'autenticità del certificato.

### Considerazioni speciali

- **Subject Alternative Names (SANs)** estendono l'applicabilità di un certificato a più identità, cruciale per server con domini multipli. Processi di emissione sicuri sono vitali per evitare rischi di impersonificazione da parte di un attacker che manipola la specifica SAN.

### Autorità di Certificazione (CAs) in Active Directory (AD)

AD CS riconosce i certificati delle CA in una foresta AD tramite contenitori designati, ognuno con ruoli specifici:

- **Certification Authorities** container contiene i certificati delle root CA trusted.
- **Enrolment Services** container mostra le Enterprise CA e i loro certificate templates.
- **NTAuthCertificates** oggetto include i certificati CA autorizzati per l'autenticazione in AD.
- **AIA (Authority Information Access)** container facilita la validazione della catena di certificati con i certificati intermedi e cross CA.

### Acquisizione del certificato: flusso di richiesta del certificato client

1. Il processo di richiesta inizia con i client che individuano una Enterprise CA.
2. Viene creato un CSR, contenente una public key e altri dettagli, dopo la generazione della coppia di chiavi pubblica-privata.
3. La CA valuta il CSR rispetto ai certificate templates disponibili, emettendo il certificato in base ai permessi del template.
4. Una volta approvata, la CA firma il certificato con la sua chiave privata e lo restituisce al client.

### Certificate Templates

Definiti all'interno di AD, questi template specificano le impostazioni e i permessi per l'emissione dei certificati, inclusi gli EKU consentiti e i diritti di enrollment o modifica, critici per gestire l'accesso ai servizi di certificazione.

La versione dello schema del template è importante. I template legacy **v1** (ad esempio il built-in **WebServer** template) mancano di diversi controlli moderni. La ricerca **ESC15/EKUwu** ha mostrato che sui template **v1** un requester può inserire **Application Policies/EKUs** nel CSR che vengono **preferite rispetto** agli EKU configurati nel template, permettendo certificati client-auth, enrollment agent o code-signing con soli diritti di enrollment. Preferire template **v2/v3**, rimuovere o sovrascrivere i defaults v1 e restringere strettamente gli EKU allo scopo previsto.

## Certificate Enrollment

Il processo di enrollment per i certificati è avviato da un amministratore che **crea un certificate template**, il quale viene poi **pubblicato** da una Enterprise Certificate Authority (CA). Questo rende il template disponibile per l'enrollment dei client, operazione ottenuta aggiungendo il nome del template al campo `certificatetemplates` di un oggetto Active Directory.

Perché un client possa richiedere un certificato, devono essere concessi i **diritti di enrollment**. Questi diritti sono definiti dai security descriptor sul certificate template e sulla Enterprise CA stessa. I permessi devono essere concessi in entrambi i punti affinché la richiesta abbia successo.

### Diritti di enrollment sul template

Questi diritti sono specificati tramite Access Control Entries (ACE), dettagliando permessi come:

- i diritti **Certificate-Enrollment** e **Certificate-AutoEnrollment**, ciascuno associato a GUID specifici.
- **ExtendedRights**, che consentono tutti i permessi estesi.
- **FullControl/GenericAll**, che forniscono controllo completo sul template.

### Diritti di enrollment sulla Enterprise CA

I diritti della CA sono delineati nel suo security descriptor, accessibile tramite la console di gestione della Certificate Authority. Alcune impostazioni consentono persino a utenti a basso privilegio l'accesso remoto, il che potrebbe rappresentare un problema di sicurezza.

### Controlli aggiuntivi di emissione

Possono applicarsi certi controlli, come:

- **Manager Approval**: mette le richieste in uno stato pending finché non sono approvate da un certificate manager.
- **Enrolment Agents and Authorized Signatures**: specificano il numero di firme richieste su un CSR e gli Application Policy OID necessari.

### Metodi per richiedere certificati

I certificati possono essere richiesti tramite:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando le interfacce DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), tramite named pipes o TCP/IP.
3. l'**interfaccia web di certificate enrollment**, con il role Certificate Authority Web Enrollment installato.
4. il **Certificate Enrollment Service** (CES), in combinazione con il servizio Certificate Enrollment Policy (CEP).
5. il **Network Device Enrollment Service** (NDES) per dispositivi di rete, usando il Simple Certificate Enrollment Protocol (SCEP).

Gli utenti Windows possono anche richiedere certificati tramite la GUI (`certmgr.msc` o `certlm.msc`) o strumenti da riga di comando (`certreq.exe` o il comando PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD) supporta l'autenticazione tramite certificato, utilizzando principalmente i protocolli **Kerberos** e **Secure Channel (Schannel)**.

### Kerberos Authentication Process

Nel processo di autenticazione Kerberos, la richiesta di un utente per un Ticket Granting Ticket (TGT) viene firmata utilizzando la **private key** del certificato dell'utente. Questa richiesta subisce diverse verifiche da parte del domain controller, inclusa la **validità**, il **path** e lo **stato di revoca** del certificato. Le verifiche comprendono anche la conferma che il certificato provenga da una fonte attendibile e la presenza dell'emittente nello **NTAUTH certificate store**. Verifiche successful portano al rilascio di un TGT. L'oggetto **`NTAuthCertificates`** in AD, presente in:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
è centrale per stabilire la fiducia per l'autenticazione tramite certificato.

### Autenticazione Secure Channel (Schannel)

Schannel facilita connessioni TLS/SSL sicure, dove durante un handshake il client presenta un certificato che, se convalidato con successo, autorizza l'accesso. La mappatura di un certificato a un account AD può coinvolgere la funzione **S4U2Self** di Kerberos o il **Subject Alternative Name (SAN)** del certificato, tra altri metodi.

### Enumerazione dei servizi di certificazione AD

I servizi di certificazione di AD possono essere enumerati tramite query LDAP, rivelando informazioni sulle **Enterprise Certificate Authorities (CAs)** e le loro configurazioni. Questo è accessibile a qualsiasi utente autenticato di dominio senza privilegi speciali. Strumenti come **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** sono usati per l'enumerazione e la valutazione delle vulnerabilità in ambienti AD CS.

I comandi per usare questi strumenti includono:
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
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Vulnerabilità recenti & Aggiornamenti di sicurezza (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* by spoofing machine account certificates during PKINIT. | La patch è inclusa negli aggiornamenti di sicurezza del **10 maggio 2022**. Controlli di auditing e strong-mapping sono stati introdotti tramite **KB5014754**; gli ambienti dovrebbero ora trovarsi in modalità *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in the AD CS Web Enrollment (certsrv) and CES roles. | I PoC pubblici sono limitati, ma i componenti IIS vulnerabili sono spesso esposti internamente. Patch disponibile da **luglio 2023** (Patch Tuesday).  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | On **v1 templates**, a requester with enrollment rights can embed **Application Policies/EKUs** in the CSR that are preferred over the template EKUs, producing client-auth, enrollment agent, or code-signing certificates. | Patched dal **12 novembre 2024**. Sostituire o supersedere i template v1 (es. default WebServer), limitare gli EKU all'intento e ridurre i diritti di enrollment. |

### Microsoft hardening timeline (KB5014754)

Microsoft ha introdotto un rollout in tre fasi (Compatibility → Audit → Enforcement) per spostare l'autenticazione Kerberos basata su certificati lontano da mappature implicite deboli. A partire dall'**11 febbraio 2025**, i domain controller passano automaticamente a **Full Enforcement** se il valore di registro `StrongCertificateBindingEnforcement` non è impostato. Gli amministratori dovrebbero:

1. Patchare tutti i DC e i server AD CS (May 2022 o successivi).
2. Monitorare Event ID 39/41 per mappature deboli durante la fase *Audit*.
3. Riemettere i certificati client-auth con la nuova **SID extension** o configurare mappature manuali forti prima di febbraio 2025.

---

## Rilevamento & Miglioramenti per l'hardening

* **Defender for Identity AD CS sensor (2023-2024)** ora espone valutazioni di postura per ESC1-ESC8/ESC11 e genera alert in tempo reale come *“Domain-controller certificate issuance for a non-DC”* (ESC8) e *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Assicurarsi che i sensor siano distribuiti su tutti i server AD CS per beneficiare di queste rilevazioni.
* Disabilitare o limitare strettamente l'opzione **“Supply in the request”** su tutti i template; preferire SAN/EKU esplicitamente definiti.
* Rimuovere **Any Purpose** o **No EKU** dai template a meno che non siano assolutamente necessari (indirizza scenari ESC2).
* Richiedere **manager approval** o workflow dedicati di Enrollment Agent per template sensibili (es. WebServer / CodeSigning).
* Restringere web enrollment (`certsrv`) e gli endpoint CES/NDES a reti fidate o dietro autenticazione client-certificate.
* Forzare la cifratura dell'enrollment RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) per mitigare ESC11 (RPC relay). Il flag è **on by default**, ma spesso è disabilitato per client legacy, riaprendo il rischio di relay.
* Mettere in sicurezza gli **IIS-based enrollment endpoints** (CES/Certsrv): disabilitare NTLM quando possibile o richiedere HTTPS + Extended Protection per bloccare i relay ESC8.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
