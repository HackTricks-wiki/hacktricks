# Certificati AD

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

### Componenti di un certificato

- Il **Subject** del certificato indica il suo proprietario.
- Una **Public Key** è associata a una chiave privata per collegare il certificato al suo legittimo proprietario.
- Il **Validity Period**, definito dalle date **NotBefore** e **NotAfter**, indica il periodo di validità del certificato.
- Un **Serial Number** univoco, assegnato dall'Autorità di certificazione (CA), identifica ogni certificato.
- L'**Issuer** è la CA che ha emesso il certificato.
- **SubjectAlternativeName** consente di aggiungere nomi per il subject, rendendo più flessibile l'identificazione.
- **Basic Constraints** specifica se il certificato è destinato a una CA o a un'entità finale e definisce le limitazioni d'uso.
- **Extended Key Usages (EKUs)** definisce gli scopi specifici del certificato, come la firma del codice o la crittografia delle email, tramite Object Identifiers (OIDs).
- **Signature Algorithm** specifica il metodo usato per firmare il certificato.
- La **Signature**, creata con la chiave privata dell'issuer, garantisce l'autenticità del certificato.<sup>[[4]](#references)</sup>

### Considerazioni speciali

- I **Subject Alternative Names (SANs)** estendono l'applicabilità di un certificato a più identità, aspetto fondamentale per i server con più domini. Per evitare rischi di impersonificazione da parte di attacker che manipolano la specifica SAN, sono essenziali procedure di emissione sicure.<sup>[[4]](#references)</sup>

### Autorità di certificazione (CAs) in Active Directory (AD)

AD CS riconosce i certificati CA in una foresta AD tramite contenitori dedicati, ciascuno con un ruolo specifico:<sup>[[4]](#references)</sup>

- Il contenitore **Certification Authorities** contiene i certificati delle CA root attendibili.
- Il contenitore **Enrolment Services** elenca le CA Enterprise e i relativi certificate template.
- L'oggetto **NTAuthCertificates** include i certificati CA autorizzati per l'autenticazione AD.
- Il contenitore **AIA (Authority Information Access)** facilita la convalida della catena di certificati tramite certificati CA intermedi e cross-CA.

### Ottenimento di un certificato: flusso di richiesta di un certificato client

1. Il processo di richiesta inizia quando i client individuano una CA Enterprise.
2. Dopo aver generato una coppia di chiavi pubblica-privata, viene creato un CSR contenente una chiave pubblica e altri dettagli.
3. La CA confronta il CSR con i certificate template disponibili e rilascia il certificato in base alle autorizzazioni del template.
4. Una volta approvato, la CA firma il certificato con la propria chiave privata e lo restituisce al client.<sup>[[4]](#references)</sup>

### Certificate template

Definiti in AD, questi template specificano le impostazioni e le autorizzazioni per l'emissione dei certificati, inclusi gli EKUs consentiti e i diritti di registrazione o modifica, fondamentali per gestire l'accesso ai servizi di certificazione.<sup>[[4]](#references)</sup>

**La versione dello schema del template è importante.** I template legacy **v1** (ad esempio, il template integrato **WebServer**) non includono diverse opzioni moderne di applicazione delle policy. La ricerca su **ESC15/EKUwu** ha dimostrato che nei template **v1** un richiedente può incorporare nel CSR **Application Policies/EKUs** che hanno **priorità sugli** EKU configurati nel template, consentendo di ottenere certificati per l'autenticazione client, enrollment agent o code signing con i soli diritti di registrazione. Preferire i template **v2/v3**, rimuovere o sostituire i valori predefiniti v1 e limitare rigorosamente gli EKU allo scopo previsto.<sup>[[1]](#references)</sup>

## Registrazione dei certificati

Il processo di registrazione dei certificati viene avviato da un amministratore che **crea un certificate template**, poi **pubblicato** da una Enterprise Certificate Authority (CA). In questo modo il template diventa disponibile per la registrazione da parte dei client: per farlo, il nome del template viene aggiunto al campo `certificatetemplates` di un oggetto Active Directory.<sup>[[4]](#references)</sup>

Perché un client possa richiedere un certificato, devono essergli concessi i **diritti di registrazione**. Questi diritti sono definiti dai security descriptor del certificate template e della CA Enterprise. Perché una richiesta vada a buon fine, le autorizzazioni devono essere concesse in entrambe le posizioni.<sup>[[4]](#references)</sup>

### Diritti di registrazione del template

Questi diritti sono specificati tramite Access Control Entries (ACEs), che definiscono autorizzazioni come:<sup>[[4]](#references)</sup>

- I diritti **Certificate-Enrollment** e **Certificate-AutoEnrollment**, ciascuno associato a GUID specifici.
- **ExtendedRights**, che consente tutte le autorizzazioni estese.
- **FullControl/GenericAll**, che garantisce il controllo completo sul template.

### Diritti di registrazione della CA Enterprise

I diritti della CA sono descritti nel suo security descriptor, accessibile dalla console di gestione Certificate Authority. Alcune impostazioni consentono persino agli utenti con privilegi limitati l'accesso remoto, il che può rappresentare un problema di sicurezza.<sup>[[4]](#references)</sup>

### Controlli aggiuntivi sull'emissione

Possono essere applicati alcuni controlli, come:<sup>[[4]](#references)</sup>

- **Manager Approval**: mantiene le richieste in sospeso finché un certificate manager non le approva.
- **Enrolment Agents and Authorized Signatures**: specifica il numero di firme richieste su un CSR e gli OID di Application Policy necessari.

### Metodi per richiedere certificati

È possibile richiedere certificati tramite:<sup>[[4]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfacce DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), tramite named pipe o TCP/IP.
3. L'**interfaccia web di registrazione dei certificati**, con il ruolo Certificate Authority Web Enrollment installato.
4. Il **Certificate Enrollment Service** (CES), insieme al servizio Certificate Enrollment Policy (CEP).
5. Il **Network Device Enrollment Service** (NDES) per i dispositivi di rete, usando il Simple Certificate Enrollment Protocol (SCEP).

Gli utenti Windows possono richiedere certificati anche tramite GUI (`certmgr.msc` o `certlm.msc`) oppure con strumenti da riga di comando (`certreq.exe` o il comando PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Autenticazione tramite certificato

Active Directory (AD) supporta l'autenticazione tramite certificato, utilizzando principalmente i protocolli **Kerberos** e **Secure Channel (Schannel)**.<sup>[[4]](#references)</sup>

### Processo di autenticazione Kerberos

Nel processo di autenticazione Kerberos, la richiesta dell'utente di un Ticket Granting Ticket (TGT) viene firmata usando la **chiave privata** del certificato dell'utente. Il controller di dominio sottopone questa richiesta a diverse convalide, tra cui quelle della **validità**, del **percorso** e dello **stato di revoca** del certificato. Le convalide includono anche la verifica che il certificato provenga da una fonte attendibile e la conferma della presenza dell'emittente nell'**archivio certificati NTAUTH**. Se le convalide hanno esito positivo, viene emesso un TGT. L'oggetto **`NTAuthCertificates`** in AD si trova in:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

è fondamentale per stabilire la fiducia nell'autenticazione tramite certificati.<sup>[[4]](#references)</sup>

Dall'implementazione di **KB5014754**, l'autenticazione Kerberos moderna tramite certificati riguarda soprattutto la **robustezza del mapping**, non solo gli EKU.<sup>[[2]](#references)</sup> Nelle foreste con hardening:

- Un certificato che contiene solo un **UPN/DNS SAN** potrebbe non essere più sufficiente per l'accesso.
- Il KDC preferisce un **strong binding**, in genere l'estensione di sicurezza SID (`1.3.6.1.4.1.311.25.2`) o un mapping esplicito forte in `altSecurityIdentities`.
- Se il certificato non dispone di un mapping forte, i DC registrano **Kdcsvc Event ID 39/41** in modalità di compatibilità e negano l'autenticazione in modalità di enforcement.
- Nei percorsi di attacco misti, **ESC9/ESC16** sono rilevanti perché rimuovono l'estensione SID dai certificati emessi; gli operatori si affidano quindi a mapping espliciti o ai formati SID SAN URL, quando il percorso di attacco li supporta.

### Autenticazione Secure Channel (Schannel)

Schannel facilita connessioni TLS/SSL sicure. Durante l'handshake, il client presenta un certificato che, se convalidato correttamente, autorizza l'accesso.<sup>[[5]](#references)</sup> Il mapping di un certificato a un account AD può avvenire tramite la funzione **S4U2Self** di Kerberos o il **Subject Alternative Name (SAN)** del certificato, tra gli altri metodi.<sup>[[4]](#references)</sup>

Schannel è anche il fallback pratico quando **PKINIT** non è disponibile. Ad esempio, se un domain controller non dispone di un certificato **Smart Card Logon** idoneo, `certipy auth` e gli strumenti PKINIT potrebbero non riuscire a ottenere un TGT, ma lo stesso certificato può comunque essere usato per l'autenticazione e le operazioni LDAP tramite **LDAPS** o **LDAP StartTLS**.

### Enumerazione dei servizi certificati AD

I servizi certificati di AD possono essere enumerati tramite query LDAP, che rivelano informazioni sulle **Enterprise Certificate Authorities (CA)** e sulle relative configurazioni. Questa operazione è accessibile a qualsiasi utente autenticato nel dominio, senza privilegi speciali.<sup>[[4]](#references)</sup> Strumenti come **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** vengono usati per l'enumerazione e la valutazione delle vulnerabilità negli ambienti AD CS.<sup>[[6]](#references)</sup>

I comandi per usare questi strumenti includono:

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

### Flag di enumerazione di Certify e PKINIT con Rubeus

Le seguenti varianti dei comandi di Certify mantengono filtri e opzioni di output distinti.<sup>[[6]](#references)</sup>

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

Rubeus può anche usare un certificato PFX protetto da password per l'autenticazione PKINIT e richiedere un TGT. L'opzione facoltativa `/getcredentials` richiede un service ticket U2U e tenta di recuperare l'hash NT dell'account:<sup>[[7]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

Per i template specifici di ESC e gli abusi delle CA, consulta [AD CS Domain Escalation](ad-certificates/domain-escalation.md).

---

## Vulnerabilità recenti e aggiornamenti di sicurezza (2022-2025)

| Anno | ID / Nome | Impatto | Punti chiave |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalatione dei privilegi* tramite spoofing dei certificati degli account macchina durante PKINIT. | La patch è inclusa negli aggiornamenti di sicurezza del **10 maggio 2022**. I controlli di auditing e strong mapping sono stati introdotti tramite **KB5014754**; gli ambienti dovrebbero ora essere in modalità *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Esecuzione remota di codice* nei ruoli AD CS Web Enrollment (certsrv) e CES. | I PoC pubblici sono limitati, ma i componenti IIS vulnerabili sono spesso esposti internamente. Applicare la patch del **luglio 2023**, rilasciata con il Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Nei **template v1**, un richiedente con diritti di enrollment può incorporare **Application Policies/EKU** nella CSR, che hanno la precedenza sugli EKU del template e producono certificati per l'autenticazione client, agenti di enrollment o la firma del codice. | Corretto il **12 novembre 2024**. Sostituire o superare i template v1 (ad esempio, il WebServer predefinito), limitare gli EKU allo scopo previsto e ridurre i diritti di enrollment. |

### Cronologia di hardening di Microsoft (KB5014754)

Microsoft ha introdotto una distribuzione in tre fasi (Compatibility → Audit → Enforcement) per allontanare l'autenticazione dei certificati Kerberos dalle mappature implicite deboli. Dal **11 febbraio 2025**, i domain controller passano automaticamente a **Full Enforcement** se il valore del registro `StrongCertificateBindingEnforcement` non è impostato. In seguito, Microsoft ha aggiornato la cronologia, consentendo il ritorno alla modalità di compatibilità fino all'aggiornamento di sicurezza del **9 settembre 2025**.<sup>[[2]](#references)</sup> Gli amministratori dovrebbero:

1. Applicare le patch a tutti i DC e server AD CS (maggio 2022 o versioni successive).
2. Monitorare gli Event ID 39/41 per individuare mappature deboli durante la fase di *Audit*.
3. Riemettere i certificati di autenticazione client con la nuova estensione **SID** oppure configurare mappature manuali forti prima che l'enforcement blocchi quelle deboli.

### Note per gli operatori di foreste sottoposte a hardening

- **ESC1/ESC6 da soli non raccontano più tutta la storia** negli ambienti dal 2025 in poi. Se si richiede un certificato per un altro principal, in genere serve anche un elemento di strong mapping, come l'estensione SID o una mappatura esplicita.
- **ESC15 (EKUwu)** è utile soprattutto negli ambienti senza patch, perché trasforma template **v1** innocui, come **WebServer**, in certificati utilizzabili per l'autenticazione o come agenti di enrollment tramite l'iniezione di **Application Policies**. Kerberos PKINIT continua a valutare gli EKU, ma anche **LDAP Schannel** rispetta le Application Policies, mantenendo rilevanti gli abusi basati su LDAP.<sup>[[1]](#references)</sup>
- **ESC16** è un'impostazione valida per l'intera CA: se la CA disabilita globalmente l'estensione di sicurezza SID, ogni certificato emesso ricade su comportamenti di mapping più deboli, a meno che la catena di attacco non inserisca un SID in un altro formato supportato.
- **I diritti ESC7 sono distinti:** un'autorizzazione `ManageCA` sulla CA può consentire modifiche a impostazioni come `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), mentre `ManageCertificates` controlla l'approvazione delle richieste. Un Deny esplicito sui diritti del certificate manager può bloccare tale percorso di approvazione anche in presenza di un Allow; valutare l'ACL effettiva della CA prima di concatenare impostazioni e template. Vedi [Microsoft's CA ACL assessment](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Miglioramenti al rilevamento e all'hardening

* Il **sensore AD CS di Defender for Identity (2023-2024)** ora mostra valutazioni della postura di sicurezza per ESC1-ESC8/ESC11 e genera avvisi in tempo reale, come *“Emissione di un certificato per un non-DC da parte di un domain controller”* (ESC8) e *“Impedire l'enrollment di certificati con Application Policies arbitrarie”* (ESC15). Per beneficiare di questi rilevamenti, assicurarsi che i sensori siano distribuiti su tutti i server AD CS.<sup>[[3]](#references)</sup>
* Disabilitare o limitare rigorosamente l'opzione **“Supply in the request”** in tutti i template; preferire valori SAN/EKU definiti esplicitamente.
* Rimuovere **Any Purpose** o **No EKU** dai template, salvo assoluta necessità (per contrastare gli scenari ESC2).
* Richiedere l'**approvazione di un manager** o flussi di lavoro dedicati per gli Enrollment Agent per i template sensibili (ad esempio, WebServer / CodeSigning).
* Limitare gli endpoint Web Enrollment (`certsrv`) e CES/NDES alle reti attendibili oppure proteggerli con l'autenticazione tramite certificato client.
* Applicare la cifratura dell'enrollment RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) per mitigare ESC11 (relay RPC). Il flag è **attivo per impostazione predefinita**, ma spesso viene disabilitato per i client legacy, riaprendo il rischio di relay.
* Proteggere gli **endpoint di enrollment basati su IIS** (CES/Certsrv): disabilitare NTLM ove possibile oppure richiedere HTTPS + Extended Protection per bloccare i relay ESC8.

Valutare ESC11 sull'host che esegue la CA, che potrebbe essere un server membro del dominio anziché un domain controller. Leggere `InterfaceFlags` della CA attiva in `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; un valore illeggibile o assente indica un risultato sconosciuto, non dimostra che la cifratura RPC sia disabilitata. Un bit `IF_ENFORCEENCRYPTICERTREQUEST` non impostato è un indizio di configurazione che richiede comunque un endpoint RPC di enrollment raggiungibile, credenziali forzabili e un template di certificato utilizzabile. Per ESC8, una challenge NTLM su HTTP da sola non è sufficiente: verificare che esista un endpoint di enrollment funzionante.

---

## References

- [1] [EKUwu: Non solo un altro AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Modifiche all'autenticazione basata su certificati nei domain controller Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Valutazioni della postura di sicurezza dei certificati - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: abuso di Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [5] [Che cos'è l'autenticazione client SSL/TLS e come funziona?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [6] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [7] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../banners/hacktricks-training.md}}
