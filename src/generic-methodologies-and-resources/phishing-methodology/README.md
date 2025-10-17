# Phishing Metodologia

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Recon la vittima
1. Seleziona il **victim domain**.
2. Esegui una enumerazione web di base **cercando login portals** usati dalla vittima e **decidi** quale impersonare.
3. Usa OSINT per **trovare emails**.
2. Prepara l'ambiente
1. **Buy the domain** che userai per l'assessment di phishing
2. **Configure the email service** records correlati (SPF, DMARC, DKIM, rDNS)
3. Configura la VPS con **gophish**
3. Prepara la campagna
1. Prepara il **email template**
2. Prepara la **web page** per rubare le credenziali
4. Lancia la campagna!

## Generate similar domain names or buy a trusted domain

### Tecniche di variazione del nome di dominio

- **Keyword**: Il nome di dominio **contiene** una **keyword** importante del dominio originale (es., zelster.com-management.com).
- **hypened subdomain**: Cambia il **punto con un trattino** di un sottodominio (es., www-zelster.com).
- **New TLD**: Stesso dominio usando una **nuova TLD** (es., zelster.org)
- **Homoglyph**: Sostituisce una lettera nel nome di dominio con **lettere che sembrano simili** (es., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Scambia due lettere all'interno del nome di dominio (es., zelsetr.com).
- **Singularization/Pluralization**: Aggiunge o rimuove la “s” alla fine del nome di dominio (es., zeltsers.com).
- **Omission**: Rimuove una delle lettere dal nome di dominio (es., zelser.com).
- **Repetition:** Ripete una delle lettere nel nome di dominio (es., zeltsser.com).
- **Replacement**: Simile a homoglyph ma meno stealthy. Sostituisce una delle lettere nel nome di dominio, magari con una lettera vicina sulla tastiera (es., zektser.com).
- **Subdomained**: Introduce un **punto** all'interno del nome di dominio (es., ze.lster.com).
- **Insertion**: Inserisce una lettera nel nome di dominio (es., zerltser.com).
- **Missing dot**: Appende la TLD al nome di dominio. (es., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Esiste la **possibilità che uno o più bit memorizzati o in comunicazione vengano automaticamente invertiti** a causa di vari fattori come tempeste solari, raggi cosmici o errori hardware.

Quando questo concetto è **applicato alle richieste DNS**, è possibile che il **dominio ricevuto dal server DNS** non sia lo stesso del dominio inizialmente richiesto.

Per esempio, una singola modifica di bit nel dominio "windows.com" può cambiarlo in "windnws.com."

Gli attacker possono **sfruttare questo registrando più domini bit-flipping** simili al dominio della vittima. L'intento è reindirizzare utenti legittimi alla propria infrastruttura.

Per maggiori informazioni leggi [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Puoi cercare su [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio scaduto che potresti usare.\
Per assicurarti che il dominio scaduto che stai per acquistare **abbia già un buon SEO** puoi verificare come è categorizzato su:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Scoperta di Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Per **scoprire più** indirizzi email validi o **verificare quelli** che hai già trovato puoi controllare se puoi brute-forceare i smtp servers della vittima. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Inoltre, non dimenticare che se gli utenti usano **qualunque web portal per accedere alle loro mail**, puoi verificare se è vulnerabile a **username brute force**, ed eventualmente sfruttare la vulnerabilità se possibile.

## Configuring GoPhish

### Installazione

Puoi scaricarlo da [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Scaricalo e decomprimilo dentro `/opt/gophish` ed esegui `/opt/gophish/gophish`\
Ti verrà mostrata una password per l'admin sulla porta 3333 nell'output. Quindi, accedi a quella porta e usa quelle credenziali per cambiare la password dell'admin. Potrebbe essere necessario fare il tunnel di quella porta in locale:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configurazione

**TLS certificate configuration**

Prima di questo passaggio dovresti **aver già acquistato il dominio** che intendi usare e questo deve essere **indirizzato** all'**IP del VPS** dove stai configurando **gophish**.
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
**Mail configuration**

Inizia l'installazione: `apt-get install postfix`

Poi aggiungi il dominio ai seguenti file:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifica anche i valori delle seguenti variabili in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Infine modifica i file **`/etc/hostname`** e **`/etc/mailname`** con il tuo nome di dominio e **riavvia il tuo VPS.**

Ora crea un **record DNS A** di `mail.<domain>` che punti all'**indirizzo IP** del VPS e un **record DNS MX** che punti a `mail.<domain>`

Ora proviamo a inviare un'email:
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

Per creare il servizio gophish in modo che possa essere avviato automaticamente e gestito come servizio puoi creare il file `/etc/init.d/gophish` con il seguente contenuto:
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
Completa la configurazione del servizio e verifica il suo funzionamento eseguendo:
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
## Configurazione del server di posta e del dominio

### Aspetta & sii legittimo

Più vecchio è un dominio, meno probabile sarà che venga classificato come spam. Dovresti quindi attendere il più possibile (almeno 1 settimana) prima della valutazione di phishing. Inoltre, se inserisci una pagina relativa a un settore con buona reputazione, la reputazione ottenuta sarà migliore.

Nota che anche se devi aspettare una settimana, puoi completare ora tutta la configurazione.

### Configura il record Reverse DNS (rDNS)

Imposta un record rDNS (PTR) che risolva l'indirizzo IP del VPS nel nome di dominio.

### Sender Policy Framework (SPF) Record

Devi **configurare un record SPF per il nuovo dominio**. Se non sai cos'è un record SPF [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puoi usare [https://www.spfwizard.net/](https://www.spfwizard.net) per generare la tua policy SPF (usa l'IP della macchina VPS)

![](<../../images/image (1037).png>)

Questo è il contenuto che deve essere impostato all'interno di un TXT record nel dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Devi **configurare un record DMARC per il nuovo dominio**. Se non sai cos'è un record DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Devi creare un nuovo record DNS TXT puntando l'hostname `_dmarc.<domain>` con il seguente contenuto:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Devi **configurare un DKIM per il nuovo dominio**. Se non sai cos'è un record DMARC [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Questo tutorial si basa su: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> È necessario concatenare entrambi i valori B64 che la chiave DKIM genera:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testa il punteggio della configurazione email

Puoi farlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Basta accedere alla pagina e inviare un'email all'indirizzo che ti forniscono:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Puoi anche **controllare la configurazione della tua email** inviando un'email a `check-auth@verifier.port25.com` e **leggendo la risposta** (per questo dovrai **aprire** port **25** e vedere la risposta nel file _/var/mail/root_ se invii l'email come root).\
Assicurati di superare tutti i test:
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
Puoi anche inviare un **messaggio a un account Gmail sotto il tuo controllo**, e controllare le **intestazioni dell'email** nella tua casella Gmail: `dkim=pass` dovrebbe essere presente nel campo header `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) can indicate you if you your domain is being blocked by spamhouse. You can request your domain/IP to be removed at: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​You can request your domain/IP to be removed at [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Imposta un **nome identificativo** per il profilo mittente
- Decidi da quale account invierai le email di phishing. Suggerimenti: _noreply, support, servicedesk, salesforce..._
- Puoi lasciare vuoti username e password, ma assicurati di selezionare Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> It's recommended to use the "**Send Test Email**" functionality to test that everything is working.\
> I would recommend to **send the test emails to 10min mails addresses** in order to avoid getting blacklisted making tests.

### Email Template

- Imposta un **nome identificativo** per il template
- Poi scrivi un **oggetto** (niente di strano, qualcosa che ti aspetteresti di leggere in una normale email)
- Assicurati di aver selezionato "**Add Tracking Image**"
- Scrivi il **template email** (puoi usare variabili come nell'esempio seguente):
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
Nota che **per aumentare la credibilità dell'email**, è consigliato usare qualche firma presa da un'email del cliente. Suggerimenti:

- Inviare un'email a un **indirizzo inesistente** e controllare se la risposta contiene qualche firma.
- Cercare **email pubbliche** come info@ex.com o press@ex.com o public@ex.com e inviare loro un'email aspettando la risposta.
- Provare a contattare **alcuni indirizzi validi scoperti** e aspettare la risposta

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Scrivi un **nome**
- **Scrivi il codice HTML** della pagina web. Nota che puoi **importare** pagine web.
- Seleziona **Capture Submitted Data** e **Capture Passwords**
- Imposta una **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Di solito dovrai modificare il codice HTML della pagina e fare dei test in locale (magari usando un server Apache) **finché non ottieni il risultato desiderato.** Poi incolla quel codice HTML nella casella.\
> Nota che se hai bisogno di **usare risorse statiche** per l'HTML (ad esempio CSS e JS) puoi salvarle in _**/opt/gophish/static/endpoint**_ e poi accedervi da _**/static/\<filename>**_

> [!TIP]
> Per la redirection potresti **reindirizzare gli utenti alla pagina principale legittima** della vittima, oppure reindirizzarli a _/static/migration.html_ per esempio, mostrare una **spinning wheel (**[**https://loading.io/**](https://loading.io)**) per 5 secondi e poi indicare che il processo è stato completato con successo**.

### Users & Groups

- Imposta un nome
- **Importa i dati** (nota che per usare il template dell'esempio hai bisogno del firstname, last name e dell'email address di ogni utente)

![](<../../images/image (163).png>)

### Campaign

Infine, crea una campaign selezionando un nome, l'email template, la landing page, l'URL, il sending profile e il group. Nota che l'URL sarà il link inviato alle vittime

Nota che il **Sending Profile permette di inviare un'email di test per vedere come apparirà l'email di phishing finale**:

![](<../../images/image (192).png>)

> [!TIP]
> Consiglio di **inviare le email di test a indirizzi 10min mails** per evitare di finire in blacklist durante i test.

Una volta che tutto è pronto, lancia la campaign!

## Website Cloning

Se per qualche motivo vuoi clonare il sito web controlla la seguente pagina:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In alcuni phishing assessment (principalmente per Red Teams) vorrai anche **inviare file contenenti qualche tipo di backdoor** (magari un C2 o magari solo qualcosa che inneschi un'autenticazione).\
Controlla la pagina seguente per alcuni esempi:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attacco precedente è abbastanza ingegnoso dato che stai falsificando un sito reale e raccogliendo le informazioni inserite dall'utente. Sfortunatamente, se l'utente non ha inserito la password corretta o se l'applicazione che hai falsificato è configurata con 2FA, **queste informazioni non ti permetteranno di impersonare l'utente ingannato**.

Qui entrano in gioco strumenti come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena). Questi tool ti permettono di generare un attacco MitM. Fondamentalmente, l'attacco funziona nel modo seguente:

1. Tu **impersoni il form di login** della pagina reale.
2. L'utente **invia** le sue **credentials** alla tua pagina falsa e lo strumento le inoltra alla pagina reale, **verificando se le credenziali funzionano**.
3. Se l'account è configurato con **2FA**, la pagina MitM chiederà il codice e una volta che **l'utente lo inserisce** lo strumento lo invierà alla pagina reale.
4. Una volta che l'utente è autenticato tu (come attacker) avrai **catturato le credentials, il 2FA, il cookie e ogni informazione** di ogni interazione mentre lo strumento esegue il MitM.

### Via VNC

E se invece di **inviare la vittima a una pagina malevola** che assomiglia all'originale, la mandi a una **sessione VNC con un browser connesso alla pagina reale**? Potrai vedere cosa fa, rubare la password, l'MFA usata, i cookie...\
Puoi farlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Ovviamente uno dei modi migliori per sapere se sei stato scoperto è **cercare il tuo dominio nelle blacklist**. Se appare elencato, in qualche modo il tuo dominio è stato rilevato come sospetto.\
Un modo semplice per verificare se il tuo dominio appare in qualche blacklist è usare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, ci sono altri modi per capire se la vittima sta **attivamente cercando attività di phishing sospette nel mondo reale** come spiegato in:


{{#ref}}
detecting-phising.md
{{#endref}}

Puoi **comprare un dominio con un nome molto simile** al dominio della vittima **e/o generare un certificato** per un **sottodominio** di un dominio controllato da te **contenente** la **keyword** del dominio della vittima. Se la **vittima** effettua qualsiasi tipo di interazione **DNS o HTTP** con essi, saprai che **sta attivamente cercando** domini sospetti e dovrai essere molto stealth.

### Evaluate the phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious) per valutare se la tua email finirà nella cartella spam, sarà bloccata o avrà successo.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets increasingly skip email lures entirely and **directly target the service-desk / identity-recovery workflow** to defeat MFA. The attack is fully "living-off-the-land": once the operator owns valid credentials they pivot with built-in admin tooling – no malware is required.

### Attack flow
1. Recon the victim
* Harvest personal & corporate details from LinkedIn, data breaches, public GitHub, etc.
* Identify high-value identities (executives, IT, finance) and enumerate the **exact help-desk process** for password / MFA reset.
2. Real-time social engineering
* Phone, Teams or chat the help-desk while impersonating the target (often with **spoofed caller-ID** or **cloned voice**).
* Provide the previously-collected PII to pass knowledge-based verification.
* Convince the agent to **reset the MFA secret** or perform a **SIM-swap** on a registered mobile number.
3. Immediate post-access actions (≤60 min in real cases)
* Establish a foothold through any web SSO portal.
* Enumerate AD / AzureAD with built-ins (no binaries dropped):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement with **WMI**, **PsExec**, or legitimate **RMM** agents already whitelisted in the environment.

### Detection & Mitigation
* Treat help-desk identity recovery as a **privileged operation** – require step-up auth & manager approval.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** rules that alert on:
* MFA method changed + authentication from new device / geo.
* Immediate elevation of the same principal (user-→-admin).
* Record help-desk calls and enforce a **call-back to an already-registered number** before any reset.
* Implement **Just-In-Time (JIT) / Privileged Access** so newly reset accounts do **not** automatically inherit high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Le crew commodity compensano il costo delle operazioni high-touch con attacchi di massa che trasformano **search engines & ad networks nel canale di distribuzione**.

1. **SEO poisoning / malvertising** spinge un risultato falso come `chromium-update[.]site` in cima agli annunci di ricerca.
2. La vittima scarica un piccolo **first-stage loader** (spesso JS/HTA/ISO). Esempi osservati da Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Il loader esfiltra i browser cookies + i credential DB, poi scarica un **silent loader** che decide – *in realtime* – cosa deployare:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* componente di persistence (registry Run key + scheduled task)

### Hardening tips
* Bloccare domini appena registrati e applicare **Advanced DNS / URL Filtering** su *search-ads* così come su e-mail.
* Limitare l'installazione software a pacchetti MSI firmati / Store, negare l'esecuzione di `HTA`, `ISO`, `VBS` tramite policy.
* Monitorare i processi figli dei browser che aprono installer:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Cercare LOLBins frequentemente abusati dai first-stage loader (es. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Gli attacker ora concatenano **LLM & voice-clone APIs** per lures totalmente personalizzati e interazione in tempo reale.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Difesa:**
• Aggiungere **dynamic banners** che evidenzino messaggi inviati da automazione non attendibile (tramite anomalie ARC/DKIM).  
• Implementare **voice-biometric challenge phrases** per richieste telefoniche ad alto rischio.  
• Simulare continuamente lures generati dall'AI nei programmi di awareness – i template statici sono obsoleti.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Besides classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, nullifying the user’s existing token. Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitorare gli eventi AzureAD/AWS/Okta in cui **`deleteMFA` + `addMFA`** si verificano **entro pochi minuti dalla stessa IP**.



## Clipboard Hijacking / Pastejacking

Gli aggressori possono copiare silenziosamente comandi malevoli negli appunti della vittima da una pagina web compromessa o typosquatted e poi indurre l'utente a incollarli dentro **Win + R**, **Win + X** o una finestra del terminale, eseguendo codice arbitrario senza alcun download o allegato.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing per eludere crawlers/sandboxes
Gli operatori sempre più spesso mettono i loro flussi di phishing dietro a un semplice controllo del dispositivo in modo che i crawler desktop non raggiungano mai le pagine finali. Un pattern comune è un piccolo script che testa se il DOM supporta il touch e invia il risultato a un endpoint server; i client non‑mobile ricevono HTTP 500 (o una pagina vuota), mentre agli utenti mobile viene servito l'intero flusso.

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
- Imposta un cookie di sessione al primo caricamento.
- Accetta `POST /detect {"is_mobile":true|false}`.
- Restituisce 500 (o un placeholder) alle GET successive quando `is_mobile=false`; serve il phishing solo se `true`.

Euristiche di hunting e rilevamento:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: sequenza di `GET /static/detect_device.js` → `POST /detect` → HTTP 500 per i non‑mobile; i percorsi legittimi per vittime mobile restituiscono 200 con HTML/JS successivo.
- Bloccare o esaminare accuratamente le pagine che condizionano il contenuto esclusivamente su `ontouchstart` o controlli dispositivo simili.

Consigli di difesa:
- Eseguire crawler con fingerprint simili a dispositivi mobili e JS abilitato per rivelare contenuti gated.
- Segnalare risposte 500 sospette successive a `POST /detect` su domini appena registrati.

## Riferimenti

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
