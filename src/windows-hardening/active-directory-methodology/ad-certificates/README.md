# Certificati AD

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

### Componenti di un Certificato

- Il **Subject** del certificato indica il suo proprietario.
- Una **Public Key** è accoppiata a una chiave privata per collegare il certificato al legittimo proprietario.
- Il **Validity Period**, definito dalle date **NotBefore** e **NotAfter**, segna la durata effettiva del certificato.
- Un **Serial Number** univoco, fornito dalla Certificate Authority (CA), identifica ogni certificato.
- L'**Issuer** si riferisce alla CA che ha emesso il certificato.
- **SubjectAlternativeName** permette nomi aggiuntivi per il subject, aumentando la flessibilità di identificazione.
- **Basic Constraints** identificano se il certificato è per una CA o per un'entità finale e definiscono restrizioni d'uso.
- Le **Extended Key Usages (EKUs)** delineano gli scopi specifici del certificato, come code signing o crittografia email, tramite Object Identifiers (OID).
- La **Signature Algorithm** specifica il metodo per firmare il certificato.
- La **Signature**, creata con la chiave privata dell'issuer, garantisce l'autenticità del certificato.

### Considerazioni Speciali

- Le **Subject Alternative Names (SANs)** estendono l'applicabilità di un certificato a più identità, cruciale per server con domini multipli. Processi di emissione sicuri sono vitali per evitare rischi di impersonificazione da parte di un attacker che manipola la specifica SAN.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS riconosce i certificati CA in una foresta AD tramite contenitori designati, ognuno con ruoli unici:

- Il contenitore **Certification Authorities** contiene i certificati root CA trusted.
- Il contenitore **Enrolment Services** dettaglia le Enterprise CAs e i loro certificate templates.
- L'oggetto **NTAuthCertificates** include i certificati CA autorizzati per l'autenticazione AD.
- Il contenitore **AIA (Authority Information Access)** facilita la validazione della chain di certificati con certificati intermediate e cross CA.

### Acquisizione del Certificato: Flusso di Richiesta Cliente

1. Il processo di richiesta inizia con i client che trovano una Enterprise CA.
2. Viene creato un CSR, contenente una public key e altri dettagli, dopo la generazione di una coppia di chiavi public-private.
3. La CA valuta il CSR rispetto ai certificate templates disponibili, emettendo il certificato in base alle autorizzazioni del template.
4. Dopo l'approvazione, la CA firma il certificato con la propria chiave privata e lo restituisce al client.

### Certificate Templates

Definiti all'interno di AD, questi template stabiliscono le impostazioni e i permessi per l'emissione dei certificati, inclusi gli EKU consentiti e i diritti di enrollment o modifica, critici per gestire l'accesso ai servizi di certificazione.

## Certificate Enrollment

Il processo di enrollment per i certificati è avviato da un amministratore che **crea un certificate template**, che viene poi **pubblicato** da una Enterprise Certificate Authority (CA). Questo rende il template disponibile per l'enrollment dei client, passo ottenuto aggiungendo il nome del template al campo `certificatetemplates` di un oggetto Active Directory.

Perché un client richieda un certificato, devono essere concessi i **diritti di enrollment**. Questi diritti sono definiti dai security descriptor sul certificate template e sulla Enterprise CA stessa. I permessi devono essere concessi in entrambe le posizioni affinché la richiesta abbia successo.

### Template Enrollment Rights

Questi diritti sono specificati tramite Access Control Entries (ACEs), descrivendo permessi come:

- I diritti **Certificate-Enrollment** e **Certificate-AutoEnrollment**, ciascuno associato a GUID specifici.
- **ExtendedRights**, che permettono tutti i permessi estesi.
- **FullControl/GenericAll**, che forniscono il controllo completo sul template.

### Enterprise CA Enrollment Rights

I diritti della CA sono delineati nel suo security descriptor, accessibile tramite la console di gestione della Certificate Authority. Alcune impostazioni consentono persino a utenti a basso privilegio l'accesso remoto, il che potrebbe rappresentare una problematica di sicurezza.

### Controlli Aggiuntivi di Emissione

Possono applicarsi alcuni controlli, come:

- **Manager Approval**: mette le richieste in uno stato pending fino all'approvazione da parte di un certificate manager.
- **Enrolment Agents and Authorized Signatures**: specificano il numero di firme richieste su un CSR e gli Application Policy OID necessari.

### Metodi per Richiedere Certificati

I certificati possono essere richiesti tramite:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfacce DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), tramite named pipes o TCP/IP.
3. L'**interfaccia web di certificate enrollment**, con il role Certificate Authority Web Enrollment installato.
4. Il **Certificate Enrollment Service** (CES), in combinazione con il servizio Certificate Enrollment Policy (CEP).
5. Il **Network Device Enrollment Service** (NDES) per dispositivi di rete, usando il Simple Certificate Enrollment Protocol (SCEP).

Gli utenti Windows possono inoltre richiedere certificati via GUI (`certmgr.msc` o `certlm.msc`) o strumenti da linea di comando (`certreq.exe` o il comando PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticazione tramite certificato

Active Directory (AD) supporta l'autenticazione tramite certificato, utilizzando principalmente i protocolli **Kerberos** e **Secure Channel (Schannel)**.

### Processo di autenticazione Kerberos

Nel processo di autenticazione Kerberos, la richiesta di un Ticket Granting Ticket (TGT) da parte di un utente viene firmata usando la **chiave privata** del certificato dell'utente. Questa richiesta viene sottoposta a diverse verifiche da parte del domain controller, incluse la **validità**, il **percorso** e lo **stato di revoca** del certificato. Le verifiche includono anche la conferma che il certificato provenga da una fonte attendibile e la presenza dell'emittente nel **NTAUTH certificate store**. Le verifiche superate portano al rilascio di un TGT. L'oggetto **`NTAuthCertificates`** in AD si trova in:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
è centrale per stabilire la fiducia per l'autenticazione tramite certificato.

### Autenticazione Secure Channel (Schannel)

Schannel facilita connessioni TLS/SSL sicure, dove durante un handshake il client presenta un certificato che, se convalidato con successo, autorizza l'accesso. La mappatura di un certificato a un account AD può coinvolgere la funzione di Kerberos **S4U2Self** o il **Subject Alternative Name (SAN)** del certificato, tra gli altri metodi.

### Enumerazione dei servizi di certificato AD

I servizi di certificato di AD possono essere enumerati tramite query LDAP, rivelando informazioni sulle **Enterprise Certificate Authorities (CAs)** e le loro configurazioni. Questo è accessibile a qualsiasi utente autenticato nel dominio senza privilegi speciali. Strumenti come **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** sono usati per l'enumerazione e la valutazione delle vulnerabilità negli ambienti AD CS.

I comandi per usare questi strumenti includono:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Riferimenti

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
