# Certificati AD

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

### Componenti di un certificato

- Il **Subject** del certificato indica il proprietario.
- Una **Public Key** è associata a una chiave privata per collegare il certificato al suo legittimo proprietario.
- Il **Validity Period**, definito dalle date **NotBefore** e **NotAfter**, indica il periodo di validità del certificato.
- Un **Serial Number** univoco, fornito dalla Certificate Authority (CA), identifica ogni certificato.
- L'**Issuer** indica la CA che ha emesso il certificato.
- **SubjectAlternativeName** consente di aggiungere altri nomi per il subject, rendendo più flessibile l'identificazione.
- **Basic Constraints** indicano se il certificato è destinato a una CA o a un'entità finale e definiscono le limitazioni d'uso.
- **Extended Key Usages (EKUs)** specificano gli scopi del certificato, come la firma del codice o la cifratura delle email, tramite Object Identifier (OID).
- L'**Signature Algorithm** specifica il metodo utilizzato per firmare il certificato.
- La **Signature**, creata con la chiave privata dell'issuer, garantisce l'autenticità del certificato.<sup>[[4]](#references)</sup>

### Considerazioni speciali

- I **Subject Alternative Names (SANs)** estendono l'applicabilità di un certificato a più identità, elemento fondamentale per i server con più domini. Processi sicuri di emissione sono essenziali per evitare il rischio di impersonificazione da parte di attacker che manipolano la specifica SAN.<sup>[[4]](#references)</sup>

### Certificate Authority (CA) in Active Directory (AD)

AD CS riconosce i certificati CA in una foresta AD tramite contenitori dedicati, ciascuno con un ruolo specifico:<sup>[[4]](#references)</sup>

- Il contenitore **Certification Authorities** contiene i certificati CA radice attendibili.
- Il contenitore **Enrolment Services** elenca le CA Enterprise e i relativi certificate template.
- L'oggetto **NTAuthCertificates** include i certificati CA autorizzati per l'autenticazione AD.
- Il contenitore **AIA (Authority Information Access)** facilita la convalida della catena di certificati con certificati intermedi e cross-CA.

### Acquisizione dei certificati: flusso di richiesta di un certificato client

1. Il processo di richiesta inizia quando i client individuano una CA Enterprise.
2. Dopo aver generato una coppia di chiavi pubblica e privata, viene creato un CSR contenente una chiave pubblica e altri dettagli.
3. La CA verifica il CSR rispetto ai certificate template disponibili ed emette il certificato in base alle autorizzazioni del template.
4. Una volta approvata la richiesta, la CA firma il certificato con la propria chiave privata e lo restituisce al client.<sup>[[4]](#references)</sup>

### Certificate template

Definiti in AD, questi template descrivono le impostazioni e le autorizzazioni per l'emissione dei certificati, inclusi gli EKU consentiti e i diritti di registrazione o modifica, fondamentali per gestire l'accesso ai servizi di certificazione.<sup>[[4]](#references)</sup>

**La versione dello schema del template è importante.** I template legacy **v1** (ad esempio, il template integrato **WebServer**) non dispongono di diversi meccanismi di enforcement moderni. La ricerca su **ESC15/EKUwu** ha mostrato che nei **template v1** un richiedente può includere nel CSR **Application Policies/EKU** che hanno **precedenza su** quelle configurate nel template, ottenendo certificati client-auth, enrollment agent o code-signing con i soli diritti di registrazione. Preferite i template **v2/v3**, rimuovete o sostituite i valori predefiniti v1 e limitate rigorosamente gli EKU allo scopo previsto.<sup>[[1]](#references)</sup>

## Registrazione dei certificati

Il processo di registrazione dei certificati viene avviato da un amministratore che **crea un certificate template**, successivamente **pubblicato** da una Enterprise Certificate Authority (CA). In questo modo il template diventa disponibile per la registrazione da parte dei client; per farlo, si aggiunge il nome del template al campo `certificatetemplates` di un oggetto Active Directory.<sup>[[4]](#references)</sup>

Perché un client possa richiedere un certificato, devono essere concessi i **diritti di registrazione**. Questi diritti sono definiti dai security descriptor del certificate template e della CA Enterprise stessa. Perché una richiesta vada a buon fine, le autorizzazioni devono essere concesse in entrambe le posizioni.

### Diritti di registrazione del template

Questi diritti sono specificati tramite Access Control Entry (ACE), che definiscono autorizzazioni come:

- I diritti **Certificate-Enrollment** e **Certificate-AutoEnrollment**, ciascuno associato a GUID specifici.
- **ExtendedRights**, che consente tutte le autorizzazioni estese.
- **FullControl/GenericAll**, che fornisce il controllo completo sul template.

### Diritti di registrazione della CA Enterprise

I diritti della CA sono descritti nel relativo security descriptor, accessibile dalla console di gestione della Certificate Authority. Alcune impostazioni consentono persino l'accesso remoto a utenti con privilegi limitati, il che può rappresentare un problema di sicurezza.

### Controlli aggiuntivi sull'emissione

Possono essere applicati alcuni controlli, ad esempio:

- **Manager Approval**: mantiene le richieste in sospeso fino all'approvazione da parte di un certificate manager.
- **Enrolment Agents and Authorized Signatures**: specificano il numero di firme richieste su un CSR e gli OID delle Application Policy necessari.

### Metodi per richiedere certificati

È possibile richiedere certificati tramite:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfacce DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), tramite named pipe o TCP/IP.
3. L'**interfaccia web di certificate enrollment**, con il ruolo Certificate Authority Web Enrollment installato.
4. Il **Certificate Enrollment Service** (CES), insieme al servizio Certificate Enrollment Policy (CEP).
5. Il **Network Device Enrollment Service** (NDES) per i dispositivi di rete, usando il Simple Certificate Enrollment Protocol (SCEP).

Gli utenti Windows possono richiedere certificati anche tramite GUI (`certmgr.msc` o `certlm.msc`) o strumenti da riga di comando (`certreq.exe` o il comando PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Autenticazione tramite certificato

Active Directory (AD) supporta l'autenticazione tramite certificato, utilizzando principalmente i protocolli **Kerberos** e **Secure Channel (Schannel)**.

### Processo di autenticazione Kerberos

Nel processo di autenticazione Kerberos, la richiesta dell'utente per un Ticket Granting Ticket (TGT) viene firmata usando la **chiave privata** del certificato dell'utente. Questa richiesta viene sottoposta a diverse verifiche da parte del controller di dominio, tra cui la **validità**, la **catena** e lo **stato di revoca** del certificato. Le verifiche includono anche la conferma che il certificato provenga da una fonte attendibile e che l'emittente sia presente nell'**archivio certificati NTAUTH**. Se le verifiche hanno esito positivo, viene rilasciato un TGT. L'oggetto **`NTAuthCertificates`** in AD, che si trova in:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

è fondamentale per stabilire la fiducia nell'autenticazione con certificato.<sup>[[4]](#references)</sup>

Dall'introduzione di **KB5014754**, l'autenticazione Kerberos moderna con certificati riguarda soprattutto la **solidità della mappatura**, non solo gli EKU.<sup>[[2]](#references)</sup> Nelle foreste con protezioni rafforzate:

- Un certificato che contiene solo un **SAN UPN/DNS** potrebbe non essere più sufficiente per l'accesso.
- Il KDC preferisce un **binding forte**, in genere l'estensione di sicurezza SID (`1.3.6.1.4.1.311.25.2`) o una mappatura esplicita forte in `altSecurityIdentities`.
- Se il certificato non dispone di una mappatura forte, i DC registrano **Kdcsvc Event ID 39/41** in modalità di compatibilità e negano l'autenticazione in modalità di applicazione.
- Nei percorsi di attacco misti, **ESC9/ESC16** sono rilevanti perché rimuovono l'estensione SID dai certificati emessi; gli operatori si affidano quindi a mappature esplicite o a formati SID URL nel SAN, se supportati dal percorso di attacco.

### Autenticazione Secure Channel (Schannel)

Schannel facilita le connessioni TLS/SSL sicure: durante l'handshake, il client presenta un certificato che, se convalidato correttamente, autorizza l'accesso. La mappatura di un certificato a un account AD può avvalersi della funzione **S4U2Self** di Kerberos o del **Subject Alternative Name (SAN)** del certificato, tra gli altri metodi.<sup>[[4]](#references)</sup>

Schannel è anche l'alternativa pratica quando **PKINIT** non è disponibile. Ad esempio, se un controller di dominio non dispone di un certificato **Smart Card Logon** idoneo, gli strumenti `certipy auth`/PKINIT potrebbero non riuscire a ottenere un TGT, ma lo stesso certificato può comunque essere utilizzabile con **LDAPS** o **LDAP StartTLS** per l'autenticazione e le operazioni LDAP.

### Enumerazione dei servizi certificati AD

I servizi certificati di AD possono essere enumerati tramite query LDAP, che rivelano informazioni sulle **Enterprise Certificate Authorities (CA)** e sulle relative configurazioni. Queste informazioni sono accessibili a qualsiasi utente autenticato nel dominio, senza privilegi speciali. Strumenti come **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** vengono utilizzati per l'enumerazione e la valutazione delle vulnerabilità negli ambienti AD CS.

Tra i comandi per usare questi strumenti figurano:

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
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* tramite lo spoofing dei certificati degli account macchina durante PKINIT. | La patch è inclusa negli aggiornamenti di sicurezza del **10 maggio 2022**. I controlli di auditing e strong mapping sono stati introdotti con **KB5014754**; gli ambienti dovrebbero ora essere in modalità *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* nei ruoli AD CS Web Enrollment (certsrv) e CES. | I PoC pubblici sono limitati, ma i componenti IIS vulnerabili sono spesso esposti internamente. Installare la patch disponibile dal Patch Tuesday di **luglio 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Nei **template v1**, un richiedente con diritti di enrollment può incorporare **Application Policies/EKU** nella CSR, che prevalgono sugli EKU del template e consentono di ottenere certificati per client-auth, enrollment agent o code-signing. | Corretto con la patch del **12 novembre 2024**. Sostituire o aggiornare i template v1 (ad es. il WebServer predefinito), limitare gli EKU in base all'uso previsto e restringere i diritti di enrollment. |

### Cronologia degli aggiornamenti di sicurezza Microsoft (KB5014754)

Microsoft ha introdotto una distribuzione in tre fasi (Compatibility → Audit → Enforcement) per allontanare l'autenticazione dei certificati Kerberos dai mapping impliciti deboli. Dal **11 febbraio 2025**, i controller di dominio passano automaticamente a **Full Enforcement** se il valore di registro `StrongCertificateBindingEnforcement` non è impostato. In seguito, Microsoft ha aggiornato la cronologia, rendendo possibile il ritorno alla modalità di compatibilità fino all'aggiornamento di sicurezza del **9 settembre 2025**.<sup>[[2]](#references)</sup> Gli amministratori dovrebbero:

1. Applicare le patch a tutti i DC e server AD CS (maggio 2022 o versioni successive).
2. Monitorare gli Event ID 39/41 per individuare mapping deboli durante la fase di *Audit*.
3. Riemettere i certificati client-auth con la nuova estensione **SID** oppure configurare mapping manuali forti prima che l'enforcement blocchi quelli deboli.

### Note operative per foreste con hardening

- **ESC1/ESC6 da soli non raccontano più tutta la storia** negli ambienti dal 2025 in poi. Se si richiede un certificato per un altro principal, di solito serve anche un elemento di strong mapping, come l'estensione SID o un mapping esplicito.
- **ESC15 (EKUwu)** è utile soprattutto negli ambienti non aggiornati, perché trasforma template **v1** innocui come **WebServer** in certificati utilizzabili per l'autenticazione o come enrollment agent, iniettando **Application Policies**. Kerberos PKINIT continua a valutare gli EKU, ma **LDAP Schannel** considera anche le Application Policies, mantenendo attuali gli abusi basati su LDAP.<sup>[[1]](#references)</sup>
- **ESC16** è un'impostazione valida per l'intera CA: se la CA disabilita globalmente l'estensione di sicurezza SID, tutti i certificati emessi ricadono su comportamenti di mapping più deboli, a meno che la catena d'attacco non inserisca un SID tramite un altro formato supportato.
- **I diritti ESC7 sono distinti:** un'autorizzazione `ManageCA` sulla CA può consentire modifiche a impostazioni come `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), mentre `ManageCertificates` gestisce l'approvazione delle richieste. Un Deny esplicito sui diritti di certificate manager può bloccare quel percorso di approvazione anche in presenza di un Allow; valutare l'ACL effettiva della CA prima di concatenare impostazioni e template. Vedere la [valutazione delle ACL delle CA di Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Miglioramenti al rilevamento e all'hardening

* Il **sensore AD CS di Defender for Identity (2023-2024)** ora mostra valutazioni della postura per ESC1-ESC8/ESC11 e genera avvisi in tempo reale, come *“Emissione di un certificato per un controller di dominio a un non-DC”* (ESC8) e *“Impedire l'enrollment di certificati con Application Policies arbitrarie”* (ESC15). Per beneficiare di questi rilevamenti, assicurarsi che i sensori siano distribuiti su tutti i server AD CS.<sup>[[3]](#references)</sup>
* Disabilitare o limitare rigorosamente l'opzione **“Supply in the request”** in tutti i template; preferire valori SAN/EKU definiti esplicitamente.
* Rimuovere **Any Purpose** o **No EKU** dai template, salvo casi di assoluta necessità (mitiga gli scenari ESC2).
* Richiedere l'**approvazione del manager** o usare workflow dedicati di Enrollment Agent per i template sensibili (ad es. WebServer / CodeSigning).
* Limitare gli endpoint web enrollment (`certsrv`) e CES/NDES alle reti attendibili o proteggerli con l'autenticazione tramite certificato client.
* Applicare la cifratura RPC per l'enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) per mitigare ESC11 (RPC relay). Il flag è **abilitato per impostazione predefinita**, ma spesso viene disabilitato per i client legacy, riaprendo il rischio di relay.
* Proteggere gli endpoint di enrollment basati su **IIS** (CES/Certsrv): disabilitare NTLM, ove possibile, oppure richiedere HTTPS + Extended Protection per bloccare gli attacchi relay ESC8.

Valutare ESC11 sull'host che esegue la CA, che potrebbe essere un server membro del dominio anziché un controller di dominio. Leggere `InterfaceFlags` della CA attiva in `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; un valore non leggibile o mancante indica un risultato sconosciuto, non dimostra che la cifratura RPC sia disabilitata. Un bit `IF_ENFORCEENCRYPTICERTREQUEST` non impostato è un indizio di configurazione che richiede comunque un endpoint RPC di enrollment raggiungibile, credenziali forzabili e un template di certificato utilizzabile. Per ESC8, una challenge HTTP NTLM da sola non basta: verificare che esista un endpoint di enrollment funzionante.

---

## References

- [1] [EKUwu: non solo un altro ESC di AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: modifiche all'autenticazione basata su certificati nei controller di dominio Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Valutazioni della postura di sicurezza dei certificati - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: abuso di Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
