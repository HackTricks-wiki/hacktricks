# Certificati AD

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

### Componenti di un certificato

- Il **Subject** del certificato indica il proprietario.
- Una **Public Key** è associata a una chiave privata per collegare il certificato al legittimo proprietario.
- Il **Validity Period**, definito dalle date **NotBefore** e **NotAfter**, indica la durata di validità del certificato.
- Un **Serial Number** univoco, fornito dalla Certificate Authority (CA), identifica ogni certificato.
- L'**Issuer** indica la CA che ha emesso il certificato.
- **SubjectAlternativeName** consente di specificare nomi aggiuntivi per il subject, aumentando la flessibilità dell'identificazione.
- I **Basic Constraints** indicano se il certificato è destinato a una CA o a un'entità finale e definiscono le limitazioni d'uso.
- Gli **Extended Key Usages (EKUs)** definiscono gli scopi specifici del certificato, come la firma del codice o la crittografia delle email, tramite Object Identifiers (OIDs).
- Il **Signature Algorithm** specifica il metodo utilizzato per firmare il certificato.
- La **Signature**, creata con la chiave privata dell'issuer, garantisce l'autenticità del certificato.<sup>[[1]](#references)</sup>

### Considerazioni speciali

- I **Subject Alternative Names (SANs)** ampliano l'applicabilità di un certificato a più identità, aspetto fondamentale per i server con più domini. Processi di emissione sicuri sono essenziali per evitare i rischi di impersonificazione causati dagli attacker che manipolano la specifica SAN.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS riconosce i certificati delle CA in una foresta AD tramite container designati, ciascuno dei quali svolge un ruolo specifico:<sup>[[1]](#references)</sup>

- Il container **Certification Authorities** contiene i certificati delle CA root attendibili.
- Il container **Enrolment Services** descrive le CA Enterprise e i relativi certificate templates.
- L'oggetto **NTAuthCertificates** include i certificati delle CA autorizzati per l'autenticazione AD.
- Il container **AIA (Authority Information Access)** facilita la convalida della catena dei certificati con certificati intermedi e cross-CA.

### Acquisizione dei certificati: flusso di richiesta del certificato client

1. Il processo di richiesta inizia quando i client individuano una CA Enterprise.
2. Dopo aver generato una coppia di chiavi pubblica-privata, viene creato un CSR contenente una chiave pubblica e altri dettagli.
3. La CA valuta il CSR rispetto ai certificate templates disponibili ed emette il certificato in base ai permessi del template.
4. Dopo l'approvazione, la CA firma il certificato con la propria chiave privata e lo restituisce al client.<sup>[[1]](#references)</sup>

### Certificate Templates

Definiti all'interno di AD, questi template descrivono le impostazioni e i permessi per l'emissione dei certificati, inclusi gli EKU consentiti e i diritti di enrollment o modifica, fondamentali per gestire l'accesso ai certificate services.<sup>[[1]](#references)</sup>

## Registrazione dei certificati

Il processo di registrazione dei certificati viene avviato da un amministratore che **crea un certificate template**, successivamente **pubblicato** da una Enterprise Certificate Authority (CA). In questo modo il template diventa disponibile per la registrazione da parte dei client; ciò avviene aggiungendo il nome del template al campo `certificatetemplates` di un oggetto Active Directory.<sup>[[1]](#references)</sup>

Affinché un client possa richiedere un certificato, devono essere concessi i **diritti di enrollment**. Questi diritti sono definiti dai security descriptor del certificate template e della Enterprise CA. Perché una richiesta vada a buon fine, i permessi devono essere concessi in entrambe le posizioni.<sup>[[1]](#references)</sup>

### Diritti di enrollment del template

Questi diritti sono specificati tramite Access Control Entries (ACEs), che definiscono permessi come:<sup>[[1]](#references)</sup>

- I diritti **Certificate-Enrollment** e **Certificate-AutoEnrollment**, ciascuno associato a GUID specifici.
- **ExtendedRights**, che consentono tutti i permessi estesi.
- **FullControl/GenericAll**, che forniscono il controllo completo sul template.

### Diritti di enrollment della Enterprise CA

I diritti della CA sono descritti nel relativo security descriptor, accessibile tramite la console di gestione Certificate Authority. Alcune impostazioni consentono persino agli utenti con privilegi ridotti di accedere da remoto, il che potrebbe rappresentare un problema di sicurezza.<sup>[[1]](#references)</sup>

### Controlli aggiuntivi sull'emissione

Possono essere applicati determinati controlli, come:<sup>[[1]](#references)</sup>

- **Manager Approval**: inserisce le richieste in uno stato pending fino all'approvazione da parte di un certificate manager.
- **Enrolment Agents and Authorized Signatures**: specificano il numero di firme richieste su un CSR e gli Application Policy OID necessari.

### Metodi per richiedere certificati

I certificati possono essere richiesti tramite:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), utilizzando interfacce DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), tramite named pipe o TCP/IP.
3. La **certificate enrollment web interface**, con il ruolo Certificate Authority Web Enrollment installato.
4. Il **Certificate Enrollment Service** (CES), insieme al servizio Certificate Enrollment Policy (CEP).
5. Il **Network Device Enrollment Service** (NDES) per i dispositivi di rete, utilizzando il Simple Certificate Enrollment Protocol (SCEP).

Gli utenti Windows possono inoltre richiedere certificati tramite la GUI (`certmgr.msc` o `certlm.msc`) oppure tramite strumenti a riga di comando (`certreq.exe` o il comando `Get-Certificate` di PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticazione tramite certificato

Active Directory (AD) supporta l'autenticazione tramite certificato, utilizzando principalmente i protocolli **Kerberos** e **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Processo di autenticazione Kerberos

Nel processo di autenticazione Kerberos, la richiesta di un utente per un Ticket Granting Ticket (TGT) viene firmata utilizzando la **chiave privata** del certificato dell'utente. Questa richiesta viene sottoposta a diverse convalide da parte del domain controller, tra cui la verifica della **validità**, del **percorso** e dello **stato di revoca** del certificato. Le convalide includono anche la verifica che il certificato provenga da una fonte attendibile e la conferma della presenza dell'emittente nel **NTAUTH certificate store**. Le convalide completate con successo comportano l'emissione di un TGT. L'oggetto **`NTAuthCertificates`** in AD, disponibile in:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
è fondamentale per stabilire la fiducia nell'autenticazione tramite certificati.<sup>[[1]](#references)</sup>

### Autenticazione tramite Secure Channel (Schannel)

Schannel facilita connessioni TLS/SSL sicure, durante le quali, nel corso di un handshake, il client presenta un certificato che, se convalidato correttamente, autorizza l'accesso.<sup>[[2]](#references)</sup> La mappatura di un certificato a un account AD può coinvolgere la funzione **S4U2Self** di Kerberos o il **Subject Alternative Name (SAN)** del certificato, oltre ad altri metodi.<sup>[[1]](#references)</sup>

### Enumerazione dei servizi certificati AD

I servizi certificati di AD possono essere enumerati tramite query LDAP, rivelando informazioni sulle **Enterprise Certificate Authorities (CAs)** e sulle relative configurazioni. Queste informazioni sono accessibili a qualsiasi utente autenticato al dominio senza privilegi speciali.<sup>[[1]](#references)</sup> Strumenti come **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** vengono utilizzati per l'enumerazione e la valutazione delle vulnerabilità negli ambienti AD CS.<sup>[[3]](#references)</sup>

I comandi per utilizzare questi strumenti includono:
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
Rubeus può anche utilizzare un certificato PFX protetto da password per l'autenticazione PKINIT e richiedere un TGT. L'opzione facoltativa `/getcredentials` richiede un service ticket U2U e tenta di recuperare l'hash NT dell'account:<sup>[[4]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```
## References

- [1] [Certified Pre-Owned: Abusare dei Servizi di Certificati di Active Directory](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [Che cos'è l'autenticazione client SSL/TLS e come funziona?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../../banners/hacktricks-training.md}}
