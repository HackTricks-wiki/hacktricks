# Certificati AD

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

### Componenti di un certificato

- Il **Subject** del certificato indica il proprietario.
- Una **Public Key** è associata a una chiave privata per collegare il certificato al suo legittimo proprietario.
- Il **Validity Period**, definito dalle date **NotBefore** e **NotAfter**, indica il periodo di validità del certificato.
- Un **Serial Number** univoco, fornito dalla Certificate Authority (CA), identifica ogni certificato.
- **Issuer** indica la CA che ha rilasciato il certificato.
- **SubjectAlternativeName** consente di associare al subject nomi aggiuntivi, aumentando la flessibilità dell'identificazione.
- **Basic Constraints** indica se il certificato è destinato a una CA o a un'entità finale e definisce le restrizioni d'uso.
- **Extended Key Usages (EKUs)** definisce gli scopi specifici del certificato, ad esempio la firma del codice o la cifratura delle email, tramite Object Identifiers (OIDs).
- **Signature Algorithm** specifica il metodo usato per firmare il certificato.
- **Signature**, creata con la chiave privata dell'issuer, garantisce l'autenticità del certificato.<sup>[[4]](#references)</sup>

### Considerazioni speciali

- **Subject Alternative Names (SANs)** estende l'applicabilità di un certificato a più identità, un aspetto essenziale per i server con più domini. Processi di emissione sicuri sono fondamentali per evitare il rischio di impersonificazione da parte di attacker che manipolano la specifica SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS riconosce i certificati CA in una foresta AD tramite container designati, ciascuno con ruoli specifici:<sup>[[4]](#references)</sup>

- Il container **Certification Authorities** contiene i certificati delle CA root attendibili.
- Il container **Enrolment Services** elenca le CA Enterprise e i relativi certificate template.
- L'oggetto **NTAuthCertificates** include i certificati CA autorizzati per l'autenticazione AD.
- Il container **AIA (Authority Information Access)** facilita la convalida della catena di certificati con certificati CA intermedi e cross-CA.

### Acquisizione dei certificati: flusso di richiesta di un certificato client

1. Il processo di richiesta inizia quando i client individuano una CA Enterprise.
2. Dopo aver generato una coppia di chiavi pubblica e privata, viene creato un CSR contenente una chiave pubblica e altri dettagli.
3. La CA valuta il CSR in base ai certificate template disponibili e rilascia il certificato secondo le autorizzazioni del template.
4. Una volta approvato, la CA firma il certificato con la propria chiave privata e lo restituisce al client.<sup>[[4]](#references)</sup>

### Certificate template

Definiti in AD, questi template descrivono le impostazioni e le autorizzazioni per il rilascio dei certificati, inclusi gli EKU consentiti e i diritti di enrollment o modifica, fondamentali per gestire l'accesso ai servizi dei certificati.<sup>[[4]](#references)</sup>

**La versione dello schema del template è importante.** I template legacy **v1** (ad esempio il template integrato **WebServer**) non dispongono di diversi controlli moderni. La ricerca su **ESC15/EKUwu** ha dimostrato che nei template **v1** un requester può includere nel CSR **Application Policies/EKUs** che hanno la precedenza sugli EKU configurati nel template, consentendo di ottenere certificati per client-auth, enrollment agent o code signing con i soli diritti di enrollment. Preferire template **v2/v3**, rimuovere o sostituire i valori predefiniti v1 e limitare rigorosamente gli EKU allo scopo previsto.<sup>[[1]](#references)</sup>

## Enrollment dei certificati

Il processo di enrollment dei certificati viene avviato da un administrator che **crea un certificate template**, poi **pubblicato** da una Enterprise Certificate Authority (CA). In questo modo il template diventa disponibile per l'enrollment dei client: per farlo, si aggiunge il nome del template al campo `certificatetemplates` di un oggetto Active Directory.<sup>[[4]](#references)</sup>

Perché un client possa richiedere un certificato, devono essere concessi i **diritti di enrollment**. Questi diritti sono definiti dai security descriptor sul certificate template e sulla CA Enterprise. Perché una richiesta vada a buon fine, le autorizzazioni devono essere concesse in entrambe le posizioni.

### Diritti di enrollment del template

Questi diritti sono specificati tramite Access Control Entries (ACEs), che indicano autorizzazioni quali:

- I diritti **Certificate-Enrollment** e **Certificate-AutoEnrollment**, ciascuno associato a GUID specifici.
- **ExtendedRights**, che consente tutte le autorizzazioni estese.
- **FullControl/GenericAll**, che fornisce il controllo completo sul template.

### Diritti di enrollment della CA Enterprise

I diritti della CA sono descritti nel suo security descriptor, accessibile dalla console di gestione Certificate Authority. Alcune impostazioni consentono persino agli utenti con privilegi limitati l'accesso remoto, il che può rappresentare un problema di sicurezza.

### Controlli aggiuntivi sul rilascio

Possono essere applicati alcuni controlli, tra cui:

- **Manager Approval**: mantiene le richieste in sospeso finché non vengono approvate da un certificate manager.
- **Enrolment Agents and Authorized Signatures**: specifica il numero di firme richieste su un CSR e gli OID di Application Policy necessari.

### Metodi per richiedere certificati

È possibile richiedere certificati tramite:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfacce DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), tramite named pipe o TCP/IP.
3. L'**interfaccia web di enrollment dei certificati**, con il ruolo Certificate Authority Web Enrollment installato.
4. Il **Certificate Enrollment Service** (CES), insieme al servizio Certificate Enrollment Policy (CEP).
5. Il **Network Device Enrollment Service** (NDES) per i dispositivi di rete, usando il Simple Certificate Enrollment Protocol (SCEP).

Gli utenti Windows possono richiedere certificati anche tramite la GUI (`certmgr.msc` o `certlm.msc`) o gli strumenti a riga di comando (`certreq.exe` o il comando PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Autenticazione tramite certificato

Active Directory (AD) supporta l'autenticazione tramite certificato, utilizzando principalmente i protocolli **Kerberos** e **Secure Channel (Schannel)**.

### Processo di autenticazione Kerberos

Nel processo di autenticazione Kerberos, la richiesta di un utente per un Ticket Granting Ticket (TGT) viene firmata usando la **chiave privata** del certificato dell'utente. Questa richiesta viene sottoposta a diverse verifiche da parte del controller di dominio, tra cui **validità**, **percorso** e **stato di revoca** del certificato. Le verifiche includono anche l'accertamento che il certificato provenga da una fonte attendibile e la conferma che l'autorità emittente sia presente nell'**archivio certificati NTAUTH**. Se le verifiche hanno esito positivo, viene rilasciato un TGT. L'oggetto **`NTAuthCertificates`** in AD si trova in:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

è fondamentale per stabilire la fiducia per l’autenticazione tramite certificato.<sup>[[4]](#references)</sup>

Dall’implementazione di **KB5014754**, l’autenticazione moderna Kerberos tramite certificato riguarda soprattutto la **forza del mapping**, non solo gli EKU.<sup>[[2]](#references)</sup> Nelle foreste hardened:

- Un certificato che contiene solo un **UPN/DNS SAN** potrebbe non essere più sufficiente per l’accesso.
- Il KDC preferisce un **strong binding**, in genere tramite la **SID security extension** (`1.3.6.1.4.1.311.25.2`) o un mapping esplicito forte in `altSecurityIdentities`.
- Se il certificato non ha un mapping forte, in modalità di compatibilità i DC registrano **Kdcsvc Event ID 39/41**, mentre in modalità di enforcement negano l’autenticazione.
- Nei percorsi di attacco misti, **ESC9/ESC16** sono rilevanti perché rimuovono la SID extension dai certificati emessi; gli operatori ricorrono quindi a mapping espliciti o ai formati SAN URL SID, quando il percorso di attacco li supporta.

### Autenticazione Schannel (Secure Channel)

Schannel consente connessioni TLS/SSL sicure. Durante l’handshake, il client presenta un certificato che, se convalidato correttamente, autorizza l’accesso. Il mapping di un certificato a un account AD può avvenire tramite la funzione Kerberos **S4U2Self** o il **Subject Alternative Name (SAN)** del certificato, tra gli altri metodi.<sup>[[4]](#references)</sup>

Schannel è anche la soluzione pratica di ripiego quando **PKINIT** non è disponibile. Ad esempio, se un domain controller non dispone di un certificato **Smart Card Logon** idoneo, gli strumenti `certipy auth`/PKINIT potrebbero non riuscire a ottenere un TGT, ma lo stesso certificato può comunque essere utilizzabile con **LDAPS** o **LDAP StartTLS** per l’autenticazione e le operazioni LDAP.

### Enumerazione dei servizi certificati AD

I servizi certificati di AD possono essere enumerati tramite query LDAP, che rivelano informazioni sulle **Enterprise Certificate Authorities (CA)** e sulle relative configurazioni. Queste informazioni sono accessibili a qualsiasi utente autenticato nel dominio, senza privilegi speciali. Strumenti come **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** vengono usati per l’enumerazione e la valutazione delle vulnerabilità negli ambienti AD CS.

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

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Vulnerabilità recenti e aggiornamenti di sicurezza (2022-2025)

| Anno | ID / Nome | Impatto | Punti chiave |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalation dei privilegi* mediante lo spoofing dei certificati degli account computer durante PKINIT. | La patch è inclusa negli aggiornamenti di sicurezza del **10 maggio 2022**. I controlli di auditing e di strong mapping sono stati introdotti con **KB5014754**; gli ambienti dovrebbero ora essere in modalità *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Esecuzione di codice remota* nei ruoli AD CS Web Enrollment (certsrv) e CES. | I PoC pubblici sono limitati, ma i componenti IIS vulnerabili sono spesso esposti internamente. Applicare la patch rilasciata con il Patch Tuesday di **luglio 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Nei **template v1**, un richiedente con diritti di enrollment può inserire **Application Policies/EKU** nella CSR, che hanno la precedenza sugli EKU del template, producendo certificati per l'autenticazione client, per l'Enrollment Agent o per la firma del codice. | Corretto con la patch del **12 novembre 2024**. Sostituire o rendere obsoleti i template v1 (ad es. il WebServer predefinito), limitare gli EKU in base allo scopo e limitare i diritti di enrollment. |

### Cronologia degli hardening Microsoft (KB5014754)

Microsoft ha introdotto una distribuzione in tre fasi (Compatibility → Audit → Enforcement) per allontanare l'autenticazione tramite certificati Kerberos dai mapping impliciti deboli. Dall'**11 febbraio 2025**, i domain controller passano automaticamente a **Full Enforcement** se il valore di registro `StrongCertificateBindingEnforcement` non è impostato. In seguito, Microsoft ha aggiornato la cronologia affinché il ritorno alla modalità Compatibility resti possibile fino all'aggiornamento di sicurezza del **9 settembre 2025**.<sup>[[2]](#references)</sup> Gli amministratori dovrebbero:

1. Applicare le patch a tutti i DC e ai server AD CS (da maggio 2022 in poi).
2. Monitorare gli Event ID 39/41 per individuare mapping deboli durante la fase *Audit*.
3. Riemettere i certificati di autenticazione client con la nuova **estensione SID** oppure configurare mapping manuali forti prima che l'Enforcement blocchi i mapping deboli.

### Note operative per le foreste con hardening

- **ESC1/ESC6 da soli non raccontano più tutta la storia** negli ambienti 2025+. Se si richiede un certificato per un altro principal, di solito serve anche un elemento di strong mapping, come l'estensione SID o un mapping esplicito.
- **ESC15 (EKUwu)** è utile soprattutto negli ambienti privi di patch, perché consente di trasformare template **v1** innocui, come **WebServer**, in certificati utilizzabili per l'autenticazione o come enrollment agent, inserendo **Application Policies**. Kerberos PKINIT continua a valutare gli EKU, ma **LDAP Schannel** tiene conto anche delle Application Policies, mantenendo rilevanti gli abusi basati su LDAP.<sup>[[1]](#references)</sup>
- **ESC16** è un'impostazione a livello di CA: se la CA disabilita globalmente l'estensione di sicurezza SID, tutti i certificati emessi ricadono su comportamenti di mapping più deboli, a meno che la catena di attacco non inserisca un SID tramite un altro formato supportato.
- **I diritti ESC7 sono distinti:** una concessione `ManageCA` sulla CA può consentire modifiche alle impostazioni, come `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), mentre `ManageCertificates` regola l'approvazione delle richieste. Un Deny esplicito sui diritti di certificate manager può bloccare tale modalità di approvazione anche in presenza di un Allow; valutare l'ACL effettiva della CA prima di concatenare impostazioni e template. Vedere la [valutazione dell'ACL della CA di Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Miglioramenti al rilevamento e all'hardening

* Il **sensore AD CS di Defender for Identity (2023-2024)** ora mostra valutazioni del livello di sicurezza per ESC1-ESC8/ESC11 e genera avvisi in tempo reale, come *“Emissione di certificati per un domain controller non-DC”* (ESC8) e *“Impedire l'enrollment di certificati con Application Policies arbitrarie”* (ESC15). Per usufruire di questi rilevamenti, assicurarsi che i sensori siano installati su tutti i server AD CS.<sup>[[3]](#references)</sup>
* Disabilitare o limitare rigorosamente l'opzione **“Supply in the request”** in tutti i template; preferire valori SAN/EKU definiti esplicitamente.
* Rimuovere **Any Purpose** o **No EKU** dai template, salvo assoluta necessità (per mitigare gli scenari ESC2).
* Richiedere l'**approvazione del manager** o flussi di lavoro dedicati per l'Enrollment Agent per i template sensibili (ad es. WebServer / CodeSigning).
* Limitare gli endpoint di web enrollment (`certsrv`) e CES/NDES alle reti attendibili o proteggerli con autenticazione tramite certificato client.
* Imporre la cifratura dell'enrollment RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) per mitigare ESC11 (relay RPC). Il flag è **attivo per impostazione predefinita**, ma spesso viene disabilitato per i client legacy, riaprendo il rischio di relay.
* Proteggere gli **endpoint di enrollment basati su IIS** (CES/Certsrv): disabilitare NTLM ove possibile oppure richiedere HTTPS + Extended Protection per bloccare i relay ESC8.

Valutare ESC11 sull'host che esegue la CA, che potrebbe essere un server membro del dominio anziché un domain controller. Leggere `InterfaceFlags` della CA attiva in `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; un valore non leggibile o mancante indica un risultato sconosciuto, non prova che la cifratura RPC sia disabilitata. Un bit `IF_ENFORCEENCRYPTICERTREQUEST` non impostato è un indizio di configurazione che richiede comunque un endpoint RPC di enrollment raggiungibile, credenziali coercibili e un template di certificato utilizzabile. Per ESC8, una challenge NTLM su HTTP da sola non è sufficiente: verificare che esista un endpoint di enrollment funzionante.

---

## References

- [1] [EKUwu: non solo un altro ESC di AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: modifiche all'autenticazione basata su certificati nei domain controller Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Valutazioni del livello di sicurezza dei certificati - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: abuso di Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
