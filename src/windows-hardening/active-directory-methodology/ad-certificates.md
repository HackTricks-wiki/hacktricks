# Certificati AD

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

### Componenti di un certificato

- Il **Subject** del certificato indica il suo proprietario.
- Una **Public Key** è associata a una chiave privata per collegare il certificato al legittimo proprietario.
- Il **Validity Period**, definito dalle date **NotBefore** e **NotAfter**, indica il periodo di validità del certificato.
- Un **Serial Number** univoco, fornito dalla Certificate Authority (CA), identifica ogni certificato.
- L'**Issuer** si riferisce alla CA che ha emesso il certificato.
- **SubjectAlternativeName** consente di associare ulteriori nomi al subject, aumentando la flessibilità dell'identificazione.
- I **Basic Constraints** identificano se il certificato è destinato a una CA o a un'entità finale e definiscono le limitazioni d'uso.
- Gli **Extended Key Usages (EKUs)** definiscono gli scopi specifici del certificato, come la firma del codice o la cifratura delle email, tramite Object Identifiers (OIDs).
- Il **Signature Algorithm** specifica il metodo utilizzato per firmare il certificato.
- La **Signature**, creata con la chiave privata dell'issuer, garantisce l'autenticità del certificato.<sup>[[4]](#references)</sup>

### Considerazioni speciali

- I **Subject Alternative Names (SANs)** estendono l'applicabilità di un certificato a più identità, aspetto fondamentale per i server con più domini. Processi di emissione sicuri sono essenziali per evitare rischi di impersonificazione da parte di attaccanti che manipolano la specifica SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS riconosce i certificati delle CA in una foresta AD tramite container designati, ognuno dei quali svolge un ruolo specifico:<sup>[[4]](#references)</sup>

- Il container **Certification Authorities** contiene i certificati delle CA root attendibili.
- Il container **Enrolment Services** descrive le Enterprise CAs e i relativi certificate templates.
- L'oggetto **NTAuthCertificates** include i certificati delle CA autorizzati per l'autenticazione AD.
- Il container **AIA (Authority Information Access)** facilita la convalida della catena dei certificati con certificati intermedi e cross CA.

### Acquisizione di un certificato: flusso di richiesta di un certificato client

1. Il processo di richiesta inizia quando i client individuano una Enterprise CA.
2. Dopo aver generato una coppia di chiavi pubblica-privata, viene creato un CSR contenente una chiave pubblica e altri dettagli.
3. La CA valuta il CSR rispetto ai certificate templates disponibili ed emette il certificato in base alle autorizzazioni del template.
4. Dopo l'approvazione, la CA firma il certificato con la propria chiave privata e lo restituisce al client.<sup>[[4]](#references)</sup>

### Certificate Templates

Definiti all'interno di AD, questi template specificano le impostazioni e le autorizzazioni per l'emissione dei certificati, inclusi gli EKUs consentiti e i diritti di enrollment o modifica, fondamentali per gestire l'accesso ai servizi dei certificati.<sup>[[4]](#references)</sup>

**La versione dello schema del template è importante.** I template legacy **v1** (ad esempio il template **WebServer** integrato) non includono diversi meccanismi moderni di enforcement. La ricerca **ESC15/EKUwu** ha dimostrato che, sui **v1 templates**, un richiedente può incorporare **Application Policies/EKUs** nel CSR, che vengono **preferiti rispetto agli** EKUs configurati nel template, consentendo di ottenere certificati per l'autenticazione client, enrollment agent o code-signing disponendo dei soli diritti di enrollment. Preferire i template **v2/v3**, rimuovere o sostituire i valori predefiniti v1 e limitare rigorosamente gli EKUs allo scopo previsto.<sup>[[1]](#references)</sup>

## Enrollment dei certificati

Il processo di enrollment dei certificati viene avviato da un amministratore che **crea un certificate template**, successivamente **pubblicato** da una Enterprise Certificate Authority (CA). In questo modo il template diventa disponibile per l'enrollment dei client; ciò avviene aggiungendo il nome del template al campo `certificatetemplates` di un oggetto Active Directory.<sup>[[4]](#references)</sup>

Affinché un client possa richiedere un certificato, devono essere concessi gli **enrollment rights**. Questi diritti sono definiti dai security descriptor del certificate template e della Enterprise CA stessa. Perché una richiesta abbia esito positivo, è necessario concedere le autorizzazioni in entrambe le posizioni.

### Diritti di enrollment del template

Questi diritti sono specificati tramite Access Control Entries (ACEs), che definiscono autorizzazioni come:

- Diritti **Certificate-Enrollment** e **Certificate-AutoEnrollment**, ciascuno associato a GUID specifici.
- **ExtendedRights**, che consentono tutte le autorizzazioni estese.
- **FullControl/GenericAll**, che forniscono il controllo completo sul template.

### Diritti di enrollment della Enterprise CA

I diritti della CA sono descritti nel relativo security descriptor, accessibile tramite la console di gestione Certificate Authority. Alcune impostazioni consentono persino agli utenti con privilegi ridotti di accedere da remoto, il che potrebbe costituire un problema di sicurezza.

### Controlli aggiuntivi sull'emissione

Possono essere applicati alcuni controlli, tra cui:

- **Manager Approval**: colloca le richieste in uno stato pending fino all'approvazione da parte di un certificate manager.
- **Enrolment Agents and Authorized Signatures**: specificano il numero di firme richieste su un CSR e gli Application Policy OIDs necessari.

### Metodi per richiedere certificati

I certificati possono essere richiesti tramite:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), utilizzando interfacce DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), tramite named pipe o TCP/IP.
3. La **certificate enrollment web interface**, con il ruolo Certificate Authority Web Enrollment installato.
4. Il **Certificate Enrollment Service** (CES), insieme al servizio Certificate Enrollment Policy (CEP).
5. Il **Network Device Enrollment Service** (NDES) per i dispositivi di rete, utilizzando il Simple Certificate Enrollment Protocol (SCEP).

Gli utenti Windows possono anche richiedere certificati tramite la GUI (`certmgr.msc` o `certlm.msc`) o gli strumenti da riga di comando (`certreq.exe` o il comando `Get-Certificate` di PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticazione tramite certificato

Active Directory (AD) supporta l'autenticazione tramite certificato, utilizzando principalmente i protocolli **Kerberos** e **Secure Channel (Schannel)**.

### Processo di autenticazione Kerberos

Nel processo di autenticazione Kerberos, la richiesta dell'utente per un Ticket Granting Ticket (TGT) viene firmata utilizzando la **chiave privata** del certificato dell'utente. Questa richiesta viene sottoposta a diverse verifiche dal domain controller, tra cui la **validità**, il **percorso** e lo **stato di revoca** del certificato. Le verifiche includono anche la conferma che il certificato provenga da una fonte attendibile e la verifica della presenza dell'emittente nel **certificate store NTAUTH**. Le verifiche completate con successo comportano l'emissione di un TGT. L'oggetto **`NTAuthCertificates`** in AD, disponibile in:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
è fondamentale per stabilire la fiducia per l'autenticazione tramite certificati.<sup>[[4]](#references)</sup>

Dal rilascio di **KB5014754**, l'autenticazione tramite certificati Kerberos moderna riguarda principalmente la **forza del mapping**, non solo gli EKU.<sup>[[2]](#references)</sup> Nei forest con hardening:

- Un certificato che contiene solo un **UPN/DNS SAN** potrebbe non essere più sufficiente per il logon.
- Il KDC preferisce un **binding forte**, in genere l'estensione di sicurezza **SID** (`1.3.6.1.4.1.311.25.2`) o un mapping esplicito forte in `altSecurityIdentities`.
- Se il certificato non dispone di un mapping forte, i DC registrano **Kdcsvc Event ID 39/41** in modalità compatibilità e negano l'autenticazione in modalità enforcement.
- Nei percorsi di attacco misti, **ESC9/ESC16** sono importanti perché rimuovono l'estensione SID dai certificati emessi; gli operatori si affidano quindi ai mapping espliciti o ai formati SID URL SAN, quando il percorso di attacco li supporta.

### Autenticazione Secure Channel (Schannel)

Schannel facilita connessioni TLS/SSL sicure, durante le quali il client presenta un certificato che, se convalidato correttamente, autorizza l'accesso. Il mapping di un certificato a un account AD può coinvolgere la funzione **S4U2Self** di Kerberos o il **Subject Alternative Name (SAN)** del certificato, tra gli altri metodi.<sup>[[4]](#references)</sup>

Schannel è anche il fallback pratico quando **PKINIT** non è disponibile. Ad esempio, se un domain controller non dispone di un certificato **Smart Card Logon** idoneo, gli strumenti `certipy auth`/PKINIT potrebbero non riuscire a ottenere un TGT, ma lo stesso certificato può comunque essere utilizzabile con **LDAPS** o **LDAP StartTLS** per l'autenticazione e le operazioni LDAP.

### Enumerazione di Active Directory Certificate Services

I certificate services di AD possono essere enumerati tramite query LDAP, rivelando informazioni sulle **Enterprise Certificate Authorities (CA)** e sulle relative configurazioni. Questa operazione è accessibile a qualsiasi utente autenticato nel dominio senza privilegi speciali. Strumenti come **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** vengono utilizzati per l'enumerazione e la valutazione delle vulnerabilità negli ambienti AD CS.

I comandi per utilizzare questi strumenti includono:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Vulnerabilità recenti e aggiornamenti di sicurezza (2022-2025)

| Anno | ID / Nome | Impatto | Punti chiave |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* tramite spoofing dei certificati degli account macchina durante PKINIT. | La patch è inclusa negli aggiornamenti di sicurezza del **10 maggio 2022**. I controlli di auditing e strong-mapping sono stati introdotti tramite **KB5014754**; gli ambienti dovrebbero ora essere in modalità *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* nei ruoli AD CS Web Enrollment (certsrv) e CES. | I PoC pubblici sono limitati, ma i componenti IIS vulnerabili sono spesso esposti internamente. Applicare la patch rilasciata durante il Patch Tuesday di **luglio 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Nei **v1 templates**, un requester con diritti di enrollment può incorporare **Application Policies/EKUs** nella CSR, che hanno priorità rispetto agli EKU del template, producendo certificati per client-auth, enrollment agent o code-signing. | Corretto a partire dal **12 novembre 2024**. Sostituire o superare i v1 templates (ad esempio il WebServer predefinito), limitare gli EKU all'intento previsto e restringere i diritti di enrollment. |

### Timeline di hardening Microsoft (KB5014754)

Microsoft ha introdotto un rollout in tre fasi (Compatibility → Audit → Enforcement) per allontanare l'autenticazione dei certificati Kerberos dai weak implicit mappings. A partire dall'**11 febbraio 2025**, i domain controller passano automaticamente a **Full Enforcement** se il valore di registro `StrongCertificateBindingEnforcement` non è impostato. Microsoft ha successivamente aggiornato la timeline, mantenendo possibile il fallback alla compatibility mode fino all'aggiornamento di sicurezza del **9 settembre 2025**.<sup>[[2]](#references)</sup> Gli amministratori dovrebbero:

1. Applicare le patch a tutti i DC e ai server AD CS (maggio 2022 o versioni successive).
2. Monitorare gli Event ID 39/41 per individuare weak mappings durante la fase di *Audit*.
3. Riemettere i certificati client-auth con la nuova **SID extension** oppure configurare strong manual mappings prima che l'enforcement blocchi i weak mappings.

### Note per gli operatori relative alle forest hardenizzate

- **ESC1/ESC6 da soli non rappresentano più l'intera situazione** negli ambienti 2025+. Se si richiede un certificato per un altro principal, di solito è necessario anche un strong mapping artifact, come la SID extension o un mapping esplicito.
- **ESC15 (EKUwu)** è soprattutto utile negli ambienti non patchati perché trasforma template **v1** innocui, come **WebServer**, in certificati capaci di autenticazione o enrollment-agent tramite l'iniezione di **Application Policies**. Kerberos PKINIT continua a valutare gli EKU, ma **LDAP Schannel** considera anche le Application Policies, mantenendo rilevante l'abuso basato su LDAP.<sup>[[1]](#references)</sup>
- **ESC16** è un'impostazione a livello di CA: se la CA disabilita globalmente la SID security extension, ogni certificato emesso ricade verso un comportamento di mapping più debole, a meno che la attack chain non inietti una SID tramite un altro formato supportato.

---

## Miglioramenti per il rilevamento e l'hardening

* Il **Defender for Identity AD CS sensor (2023-2024)** ora mostra posture assessments per ESC1-ESC8/ESC11 e genera alert in tempo reale come *“Domain-controller certificate issuance for a non-DC”* (ESC8) e *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Assicurarsi che i sensori siano distribuiti su tutti i server AD CS per sfruttare queste detection.<sup>[[3]](#references)</sup>
* Disabilitare o limitare rigorosamente l'opzione **“Supply in the request”** su tutti i template; preferire valori SAN/EKU definiti esplicitamente.
* Rimuovere **Any Purpose** o **No EKU** dai template, salvo assoluta necessità (per affrontare gli scenari ESC2).
* Richiedere **manager approval** o workflow dedicati di Enrollment Agent per i template sensibili (ad esempio WebServer / CodeSigning).
* Limitare il web enrollment (`certsrv`) e gli endpoint CES/NDES alle reti trusted oppure proteggerli tramite client-certificate authentication.
* Applicare la cifratura RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) per mitigare ESC11 (RPC relay). Il flag è **attivo per impostazione predefinita**, ma viene spesso disabilitato per i client legacy, riaprendo il rischio di relay.
* Proteggere gli endpoint di enrollment basati su **IIS** (CES/Certsrv): disabilitare NTLM quando possibile oppure richiedere HTTPS + Extended Protection per bloccare i relay ESC8.

---

## Riferimenti

- [1] [EKUwu: Not just another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
