# Metodologia di Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Recon della vittima
1. Seleziona il **victim domain**.
2. Esegui una enumerazione web di base **cercando i login portals** usati dalla vittima e **decidi** quale **impersonerai**.
3. Usa un po' di **OSINT** per **trovare email**.
2. Prepara l'ambiente
1. Compra il **domain** che userai per il phishing assessment
2. **Configura i record** correlati al servizio email (SPF, DMARC, DKIM, rDNS)
3. Configura la VPS con **gophish**
3. Prepara la campagna
1. Prepara il **email template**
2. Prepara la **web page** per rubare le credenziali
4. Lancia la campagna!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: il domain name **contiene** una **keyword** importante del domain originale (e.g., zelster.com-management.com).
- **hypened subdomain**: Cambia il **punto con un trattino** di un subdomain (e.g., www-zelster.com).
- **New TLD**: Stesso domain usando una **new TLD** (e.g., zelster.org)
- **Homoglyph**: Sostituisce una lettera nel domain con **lettere che hanno un aspetto simile** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Scambia due lettere all'interno del domain (e.g., zelsetr.com).
- **Singularization/Pluralization**: Aggiunge o rimuove “s” alla fine del domain (e.g., zeltsers.com).
- **Omission**: Rimuove una delle lettere dal domain (e.g., zelser.com).
- **Repetition:** Ripete una delle lettere nel domain (e.g., zeltsser.com).
- **Replacement**: Simile a homoglyph ma meno furtivo. Sostituisce una delle lettere nel domain, magari con una lettera vicina sulla tastiera (e.g, zektser.com).
- **Subdomained**: Introduce un **dot** all'interno del domain (e.g., ze.lster.com).
- **Insertion**: Inserisce una lettera nel domain (e.g., zerltser.com).
- **Missing dot**: Appendi la TLD al domain (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Esiste la **possibilità che alcuni bit memorizzati o in comunicazione vengano automaticamente invertiti** a causa di fattori come brillamenti solari, raggi cosmici o errori hardware.

Quando questo concetto è **applicato alle richieste DNS**, è possibile che il **domain ricevuto dal DNS server** non sia lo stesso domain richiesto inizialmente.

Per esempio, una singola modifica di bit nel domain "windows.com" può cambiarlo in "windnws.com."

Gli attaccanti possono **sfruttare questo registrando più domain soggetti a bit-flipping** simili al domain della vittima. La loro intenzione è reindirizzare utenti legittimi alla loro infrastruttura.

Per maggiori informazioni leggi [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Puoi cercare su [https://www.expireddomains.net/](https://www.expireddomains.net) un domain scaduto che potresti usare.\
Per assicurarti che il domain scaduto che intendi comprare **abbia già un buon SEO** puoi verificare come è categorizzato in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Per **scoprire più** indirizzi email validi o **verificare quelli** che hai già trovato puoi provare a brute-forzare i server smtp della vittima. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Inoltre, non dimenticare che se gli utenti usano **un web portal per accedere alle loro mail**, puoi verificare se è vulnerabile a **username brute force** ed eventualmente sfruttare la vulnerabilità.

## Configuring GoPhish

### Installation

Puoi scaricarlo da [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Scaricalo e decomprimilo dentro `/opt/gophish` ed esegui `/opt/gophish/gophish`\
Ti verrà fornita una password per l'utente admin sulla porta 3333 nell'output. Quindi, accedi a quella porta e usa quelle credenziali per cambiare la password admin. Potrebbe essere necessario fare tunneling di quella porta in locale:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configurazione

**Configurazione del certificato TLS**

Prima di questo passaggio dovresti **già aver acquistato il dominio** che intendi usare e deve essere **puntato** all'**IP del VPS** dove stai configurando **gophish**.
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

Avvia l'installazione: `apt-get install postfix`

Aggiungi quindi il dominio ai seguenti file:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifica inoltre i valori delle seguenti variabili in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Infine modifica i file **`/etc/hostname`** e **`/etc/mailname`** con il tuo nome di dominio e **riavvia il VPS.**

Ora crea un **DNS A record** di `mail.<domain>` che punti all'**indirizzo IP** del VPS e un **DNS MX** che punti a `mail.<domain>`

Ora proviamo a inviare un'email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configurazione di Gophish**

Ferma l'esecuzione di gophish e configuriamolo.\
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
Completa la configurazione del servizio e verifica che funzioni eseguendo:
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
## Configurazione del mail server e del dominio

### Wait & be legit

Più un dominio è vecchio, meno è probabile che venga classificato come spam. Dovresti quindi aspettare il più a lungo possibile (almeno 1 settimana) prima della valutazione phishing. Inoltre, se pubblichi una pagina relativa a un settore con buona reputazione, la reputazione ottenuta sarà migliore.

Nota che anche se devi aspettare una settimana, puoi completare ora tutte le configurazioni.

### Configure Reverse DNS (rDNS) record

Imposta un record rDNS (PTR) che risolva l'indirizzo IP del VPS nel nome di dominio.

### Sender Policy Framework (SPF) Record

Devi **configurare un record SPF per il nuovo dominio**. Se non sai cos'è un record SPF [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

You can use [https://www.spfwizard.net/](https://www.spfwizard.net) to generate your SPF policy (use the IP of the VPS machine)

![](<../../images/image (1037).png>)

Questo è il contenuto che deve essere impostato dentro un record TXT nel dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Record DMARC (Domain-based Message Authentication, Reporting & Conformance)

Devi **configurare un record DMARC per il nuovo dominio**. Se non sai cos'è un record DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Devi creare un nuovo record DNS TXT per l'hostname `_dmarc.<domain>` con il seguente contenuto:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Devi **configurare un record DKIM per il nuovo dominio**. Se non sai cos'è un record DMARC [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Questa guida si basa su: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Devi concatenare entrambi i valori B64 che la chiave DKIM genera:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Puoi farlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accedi alla pagina e invia un'email all'indirizzo che ti forniscono:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Puoi anche **verificare la configurazione della tua email** inviando un'email a `check-auth@verifier.port25.com` e **leggendo la risposta** (per questo dovrai **aprire** la porta **25** e vedere la risposta nel file _/var/mail/root_ se invii l'email come root).\
Controlla di superare tutti i test:
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
Puoi anche inviare **un messaggio a un account Gmail sotto il tuo controllo**, e controllare i **header dell'email** nella tua casella Gmail: `dkim=pass` dovrebbe essere presente nel campo `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Rimozione da Spamhouse Blacklist

La pagina [www.mail-tester.com](https://www.mail-tester.com) può indicarti se il tuo dominio è bloccato da spamhouse. Puoi richiedere la rimozione del tuo dominio/IP qui: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Rimozione da Microsoft Blacklist

​​Puoi richiedere la rimozione del tuo dominio/IP qui: [https://sender.office.com/](https://sender.office.com).

## Crea e Avvia una campagna GoPhish

### Profilo di invio

- Imposta un **nome identificativo** per il profilo mittente
- Decidi da quale account invierai le email di phishing. Suggerimenti: _noreply, support, servicedesk, salesforce..._
- Puoi lasciare vuoti username e password, ma assicurati di selezionare **Ignore Certificate Errors**

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> È consigliato utilizzare la funzionalità "**Send Test Email**" per verificare che tutto funzioni.\
> Consiglio di **inviare le email di test agli indirizzi 10min mails** per evitare di essere blacklisted durante i test.

### Email Template

- Imposta un **nome identificativo** per il template
- Poi scrivi un **oggetto** (niente di strano, qualcosa che potresti aspettarti di leggere in una email normale)
- Assicurati di avere selezionato "**Add Tracking Image**"
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
Nota che **per aumentare la credibilità dell'email**, è consigliabile usare qualche firma presente in un'email del cliente. Suggerimenti:

- Inviare un'email a un **indirizzo inesistente** e verificare se la risposta contiene qualche firma.
- Cercare **email pubbliche** come info@ex.com o press@ex.com o public@ex.com, inviargli un'email e aspettare la risposta.
- Provare a contattare **alcune email valide scoperte** e aspettare la risposta

![](<../../images/image (80).png>)

> [!TIP]
> Il Template Email permette anche di **allegare file da inviare**. Se vuoi anche rubare challenge NTLM usando alcuni file/documenti appositamente creati [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Inserire un **nome**
- **Inserire il codice HTML** della pagina web. Nota che puoi **importare** pagine web.
- Selezionare **Cattura dati inviati** e **Cattura password**
- Impostare una **redirezione**

![](<../../images/image (826).png>)

> [!TIP]
> Di solito dovrai modificare il codice HTML della pagina e fare dei test in locale (forse usando un server Apache) **finché non sei soddisfatto del risultato.** Poi, incolla quel codice HTML nella casella.\
> Nota che se hai bisogno di **usare risorse statiche** per l'HTML (ad esempio alcuni file CSS o JS) puoi salvarle in _**/opt/gophish/static/endpoint**_ e poi accedervi da _**/static/\<filename>**_

> [!TIP]
> Per la redirezione potresti **reindirizzare gli utenti alla pagina principale legittima** della vittima, oppure reindirizzarli a _/static/migration.html_ per esempio, mettere una **ruota che gira (**[**https://loading.io/**](https://loading.io)**) per 5 secondi e poi indicare che il processo è stato completato con successo**.

### Users & Groups

- Impostare un nome
- **Importare i dati** (nota che per usare il template d'esempio è necessario avere firstname, last name e l'indirizzo email di ogni utente)

![](<../../images/image (163).png>)

### Campaign

Infine, crea una campagna selezionando un nome, il template email, la landing page, l'URL, il profilo di invio e il gruppo. Nota che l'URL sarà il link inviato alle vittime

Nota che il **Sending Profile permette di inviare un'email di test per vedere come apparirà l'email di phishing finale**:

![](<../../images/image (192).png>)

> [!TIP]
> Consiglierei di **inviare le email di test a indirizzi 10min mails** per evitare di finire in blacklist durante i test.

Una volta che tutto è pronto, avvia semplicemente la campagna!

## Website Cloning

Se per qualsiasi motivo vuoi clonare il sito web controlla la seguente pagina:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In alcune valutazioni di phishing (soprattutto per Red Teams) vorrai anche **inviare file che contengono qualche tipo di backdoor** (forse un C2 o forse qualcosa che attiverà un'autenticazione).\
Guarda la seguente pagina per alcuni esempi:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attacco precedente è abbastanza elegante perché stai fingendo un sito reale e raccogliendo le informazioni inserite dall'utente. Sfortunatamente, se l'utente non ha inserito la password corretta o se l'applicazione che hai falsificato è configurata con 2FA, **queste informazioni non ti permetteranno di impersonare l'utente indotto in errore**.

Qui entrano in gioco strumenti come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena). Questi strumenti ti permettono di generare un attacco MitM. Fondamentalmente, l'attacco funziona nel modo seguente:

1. **Falsifichi il form di login** della pagina reale.
2. L'utente **invia** le sue **credenziali** alla tua pagina falsa e lo strumento le inoltra alla pagina reale, **verificando se le credenziali funzionano**.
3. Se l'account è configurato con **2FA**, la pagina MitM la richiederà e una volta che **l'utente la inserisce** lo strumento la inoltra alla pagina reale.
4. Una volta autenticato l'utente tu (come attaccante) avrai **catturato le credenziali, la 2FA, il cookie e qualsiasi informazione** di ogni interazione mentre lo strumento esegue il MitM.

### Via VNC

E se invece di **inviare la vittima a una pagina malevola** che somiglia all'originale, la mandi a una **sessione VNC con un browser connesso alla pagina reale**? Potrai vedere cosa fa, rubare la password, l'MFA usata, i cookie...\
Puoi farlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Ovviamente uno dei modi migliori per sapere se sei stato scoperto è **cercare il tuo dominio nelle blacklist**. Se appare elencato, in qualche modo il tuo dominio è stato rilevato come sospetto.\
Un modo semplice per verificare se il tuo dominio appare in qualche blacklist è usare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, ci sono altri modi per capire se la vittima sta **attivamente cercando attività di phishing sospette in rete** come spiegato in:


{{#ref}}
detecting-phising.md
{{#endref}}

Puoi **acquistare un dominio con un nome molto simile** a quello della vittima **e/o generare un certificato** per un **sottodominio** di un dominio controllato da te **contenente** la **keyword** del dominio della vittima. Se la **vittima** esegue qualsiasi tipo di **interazione DNS o HTTP** con essi, saprai che **sta attivamente cercando** domini sospetti e dovrai essere molto stealth.

### Valutare il phishing

Usa [**Phishious**](https://github.com/Rices/Phishious) per valutare se la tua email finirà nella cartella spam o se verrà bloccata o avrà successo.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

I gruppi di intrusione moderni saltano sempre più spesso le lusinghe via email e **mirano direttamente al service-desk / workflow di recupero identità** per sconfiggere l'MFA. L'attacco è completamente "living-off-the-land": una volta ottenute credenziali valide l'operatore pivotta con strumenti amministrativi integrati – nessun malware è richiesto.

### Flusso d'attacco
1. Ricognizione della vittima
* Raccogliere dettagli personali e aziendali da LinkedIn, data breaches, GitHub pubblico, ecc.
* Identificare identità ad alto valore (dirigenti, IT, finanza) ed enumerare il **processo esatto della help-desk** per il reset di password / MFA.
2. Social engineering in tempo reale
* Telefonare, usare Teams o chat con la help-desk impersonando la vittima (spesso con **caller-ID spoofato** o **voce clonata**).
* Fornire le PII raccolte in precedenza per superare la verifica basata sulla conoscenza.
* Convincere l'operatore a **resettare il secret MFA** o a effettuare un **SIM-swap** su un numero mobile registrato.
3. Azioni immediate post-accesso (≤60 min nei casi reali)
* Stabilire un foothold tramite qualsiasi portale web SSO.
* Enumerare AD / AzureAD con strumenti integrati (nessun binario installato):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Movimento laterale con **WMI**, **PsExec**, o agenti legittimi **RMM** già whitelisti nell'ambiente.

### Rilevamento & Mitigazione
* Trattare il recupero identità della help-desk come un'operazione **privilegiata** – richiedere step-up auth e approvazione del manager.
* Distribuire regole **Identity Threat Detection & Response (ITDR)** / **UEBA** che generino allarmi su:
* Metodo MFA cambiato + autenticazione da nuovo dispositivo / geolocalizzazione.
* Immediata elevazione dello stesso principal (user → admin).
* Registrare le chiamate alla help-desk e imporre un **richiamo verso un numero già registrato** prima di qualsiasi reset.
* Implementare **Just-In-Time (JIT) / Privileged Access** in modo che gli account appena resettati non ereditino automaticamente token ad alto privilegio.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
I gruppi commodity compensano il costo delle operazioni high-touch con attacchi di massa che trasformano **motori di ricerca & reti pubblicitarie nel canale di distribuzione**.

1. **SEO poisoning / malvertising** spinge un risultato falso come `chromium-update[.]site` in cima agli annunci di ricerca.
2. La vittima scarica un piccolo **loader di primo stadio** (spesso JS/HTA/ISO). Esempi osservati da Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Il loader esfiltra cookie del browser + DB di credenziali, poi scarica un **silent loader** che decide – *in tempo reale* – se distribuire:
* RAT (es. AsyncRAT, RustDesk)
* ransomware / wiper
* componente di persistenza (Run key del registro + scheduled task)

### Suggerimenti di hardening
* Bloccare domini appena registrati e imporre **Advanced DNS / URL Filtering** sia sugli annunci di ricerca sia sulle email.
* Limitare l'installazione del software a pacchetti MSI firmati / Store, negare l'esecuzione di `HTA`, `ISO`, `VBS` tramite policy.
* Monitorare processi figli dei browser che aprono installer:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Cercare LOLBins frequentemente abusati dai loader di primo stadio (es. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Gli attaccanti ora concatenano **API LLM & voice-clone** per esche completamente personalizzate e interazioni in tempo reale.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automazione|Generare e inviare >100 k email / SMS con testo randomizzato e link di tracciamento.|
|AI generativa|Produrre email *one-off* che fanno riferimento a M&A pubbliche, battute interne dai social; deep-fake della voce del CEO in uno scam di richiamata.|
|AI agentica|Registrare domini in autonomia, raschiare intel open-source, creare email di next-stage quando una vittima clicca ma non invia le credenziali.|

**Difesa:**
• Aggiungere **banner dinamici** che evidenzino messaggi inviati da automazione non attendibile (tramite anomalie ARC/DKIM).  
• Distribuire **frasi di sfida biometriche vocali** per richieste telefoniche ad alto rischio.  
• Simulare continuamente esche generate da AI nei programmi di consapevolezza – i template statici sono obsoleti.

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
Oltre al classico push-bombing, gli operatori semplicemente **forzano una nuova registrazione MFA** durante la chiamata alla help-desk, annullando il token esistente dell'utente. Qualsiasi successivo prompt di login appare legittimo per la vittima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.

## Clipboard Hijacking / Pastejacking

Gli attaccanti possono copiare silenziosamente comandi malevoli negli appunti (clipboard) della vittima da una pagina web compromessa o typosquatted e poi indurre l'utente a incollarli in **Win + R**, **Win + X** o in una finestra del terminale, eseguendo codice arbitrario senza alcun download o attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Gli operatori sempre più spesso mettono i loro phishing flows dietro a un semplice device check in modo che i desktop crawlers non raggiungano mai le pagine finali. Un pattern comune è un piccolo script che testa un touch-capable DOM e invia il risultato a un server endpoint; i client non-mobile ricevono HTTP 500 (o una pagina vuota), mentre agli utenti mobile viene servito l'intero flow.

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
- Restituisce 500 (o un placeholder) alle GET successive quando `is_mobile=false`; serve phishing solo se `true`.

Hunting e euristiche di rilevamento:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: sequenza di `GET /static/detect_device.js` → `POST /detect` → HTTP 500 per non‑mobile; i percorsi legittimi per vittime mobile restituiscono 200 con HTML/JS successivo.
- Bloccare o esaminare con attenzione le pagine che condizionano il contenuto esclusivamente su `ontouchstart` o controlli simili del dispositivo.

Consigli di difesa:
- Esegui i crawlers con fingerprint simili a dispositivi mobili e JS abilitato per rivelare contenuti gated.
- Genera un alert su risposte 500 sospette a seguito di `POST /detect` su domini appena registrati.

## Riferimenti

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
