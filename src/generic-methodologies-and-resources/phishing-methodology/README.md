# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Recon la vittima
1. Seleziona il **victim domain**.
2. Esegui una enumerazione web di base **cercando i portali di login** usati dalla vittima e **decidi** quale **impersonare**.
3. Usa OSINT per **trovare email**.
2. Prepara l'ambiente
1. **Compra il dominio** che userai per l'assessment di phishing
2. **Configura i record** del servizio email (SPF, DMARC, DKIM, rDNS)
3. Configura il VPS con **gophish**
3. Prepara la campagna
1. Prepara il **template email**
2. Prepara la **web page** per rubare le credenziali
4. Lancia la campagna!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Il nome di dominio **contiene** una **keyword** importante del dominio originale (es., zelster.com-management.com).
- **hypened subdomain**: Sostituisci il **punto con un trattino** di un sottodominio (es., www-zelster.com).
- **New TLD**: Stesso dominio usando una **nuova TLD** (es., zelster.org)
- **Homoglyph**: **Sostituisce** una lettera nel nome di dominio con **lettere che sembrano simili** (es., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Scambia due lettere** all'interno del nome di dominio (es., zelsetr.com).
- **Singularization/Pluralization**: Aggiunge o rimuove la “s” alla fine del dominio (es., zeltsers.com).
- **Omission**: **Rimuove una** delle lettere dal nome di dominio (es., zelser.com).
- **Repetition:** **Ripete una** delle lettere nel nome di dominio (es., zeltsser.com).
- **Replacement**: Simile a homoglyph ma meno stealthy. Sostituisce una delle lettere nel nome di dominio, magari con una lettera vicina sulla tastiera (es., zektser.com).
- **Subdomained**: Introduce un **punto** all'interno del nome di dominio (es., ze.lster.com).
- **Insertion**: **Inserisce una lettera** nel nome di dominio (es., zerltser.com).
- **Missing dot**: Aggiunge la TLD al nome di dominio. (es., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Esiste la **possibilità che alcuni bit memorizzati o in comunicazione vengano automaticamente invertiti** a causa di vari fattori come solar flares, cosmic rays o errori hardware.

Quando questo concetto viene **applicato alle richieste DNS**, è possibile che il **dominio ricevuto dal server DNS** non sia lo stesso del dominio inizialmente richiesto.

Per esempio, una singola modifica di bit nel dominio "windows.com" può cambiarlo in "windnws.com."

Gli attacker possono **sfruttare questo registrando più domini bit-flipping** simili al dominio della vittima. L'intento è deviare gli utenti legittimi verso la loro infrastruttura.

Per maggiori informazioni leggi [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Puoi cercare su [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio scaduto che potresti usare.\
Per assicurarti che il dominio scaduto che intendi acquistare **abbia già un buon SEO** puoi verificare come è categorizzato in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Per **scoprire più** indirizzi email validi o **verificare quelli** che hai già scoperto puoi controllare se è possibile fare brute-force contro gli smtp servers della vittima. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Inoltre, non dimenticare che se gli utenti usano **un qualsiasi web portal per accedere alle loro mail**, puoi verificare se è vulnerabile a **username brute force**, ed eventualmente sfruttare la vulnerabilità se possibile.

## Configuring GoPhish

### Installation

Puoi scaricarlo da [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Scaricalo e decomprimilo dentro `/opt/gophish` ed esegui `/opt/gophish/gophish`\
Ti verrà mostrata una password per l'utente admin nella porta 3333 nell'output. Quindi accedi a quella porta e usa quelle credenziali per cambiare la password dell'admin. Potrebbe essere necessario fare un tunnel di quella porta in locale.
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configurazione

**Configurazione del certificato TLS**

Prima di questo passaggio dovresti aver **già acquistato il dominio** che intendi usare e deve essere **puntato** all'**IP del VPS** dove stai configurando **gophish**.
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

Inizia installando: `apt-get install postfix`

Poi aggiungi il dominio ai seguenti file:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifica anche i valori delle seguenti variabili in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Infine modifica i file **`/etc/hostname`** e **`/etc/mailname`** con il tuo nome di dominio e **riavvia il tuo VPS.**

Ora crea un **DNS A record** di `mail.<domain>` puntando all'**indirizzo IP** del VPS e un **DNS MX** record che punti a `mail.<domain>`

Ora proviamo a inviare un'email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

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

### Attendi & sii legittimo

Più un dominio è vecchio, meno probabile è che venga classificato come spam. Dovresti quindi aspettare il più a lungo possibile (almeno 1 settimana) prima della valutazione phishing. Inoltre, se pubblichi una pagina relativa a un settore con buona reputazione, la reputazione ottenuta sarà migliore.

Nota che anche se devi aspettare una settimana puoi comunque completare ora la configurazione di tutto.

### Configura il record Reverse DNS (rDNS)

Imposta un record rDNS (PTR) che risolva l'indirizzo IP della VPS nel nome del dominio.

### Record Sender Policy Framework (SPF)

Devi **configurare un record SPF per il nuovo dominio**. Se non sai cos'è un record SPF [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puoi usare [https://www.spfwizard.net/](https://www.spfwizard.net) per generare la tua policy SPF (usa l'IP della macchina VPS)

![](<../../images/image (1037).png>)

Questo è il contenuto che deve essere impostato all'interno di un record TXT nel dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Record DMARC (Domain-based Message Authentication, Reporting & Conformance)

Devi **configurare un record DMARC per il nuovo dominio**. Se non sai cos'è un record DMARC [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Devi creare un nuovo record DNS TXT che punti all'hostname `_dmarc.<domain>` con il seguente contenuto:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Devi **configurare il DKIM per il nuovo dominio**. Se non sai cos'è un record DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Questo tutorial si basa su: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> È necessario concatenare entrambi i valori B64 che la chiave DKIM genera:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Verifica il punteggio della configurazione email

Puoi farlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accedi alla pagina e invia un'email all'indirizzo che ti forniscono:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Puoi anche **verificare la configurazione della tua email** inviando una email a `check-auth@verifier.port25.com` e **leggendo la risposta** (per questo dovrai **aprire** port **25** e vedere la risposta nel file _/var/mail/root_ se invii l'email come root).\
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
Puoi anche inviare un **messaggio a un account Gmail sotto il tuo controllo**, e controllare le **intestazioni dell'email** nella tua casella di posta Gmail; `dkim=pass` dovrebbe essere presente nell'intestazione `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Rimozione dalla blacklist di Spamhouse

La pagina [www.mail-tester.com](https://www.mail-tester.com) può indicare se il tuo dominio viene bloccato da Spamhouse. Puoi richiedere la rimozione del tuo dominio/IP qui: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Rimozione dalla blacklist di Microsoft

​​Puoi richiedere la rimozione del tuo dominio/IP su [https://sender.office.com/](https://sender.office.com).

## Creare e lanciare una campagna GoPhish

### Profilo di invio

- Imposta un **nome per identificare** il profilo mittente
- Decidi da quale account invierai le email di phishing. Suggerimenti: _noreply, support, servicedesk, salesforce..._
- Puoi lasciare vuoti nome utente e password, ma assicurati di selezionare 'Ignora errori di certificato'

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Si consiglia di usare la funzionalità "**Invia email di test**" per verificare che tutto funzioni.\
> Consiglio di **inviare le email di prova a indirizzi 10min mails** per evitare di finire in blacklist durante i test.

### Modello email

- Imposta un **nome per identificare** il modello
- Poi scrivi un **oggetto** (niente di strano, solo qualcosa che potresti aspettarti di leggere in una normale email)
- Assicurati di aver selezionato "**Aggiungi immagine di tracciamento**"
- Scrivi il **modello email** (puoi usare variabili come nell'esempio seguente):
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

- Inviare un'email a un **indirizzo inesistente** e verificare se la risposta contiene qualche firma.
- Cercare **email pubbliche** come info@ex.com o press@ex.com o public@ex.com e inviare loro un'email aspettando la risposta.
- Provare a contattare **qualche email valida scoperta** e attendere la risposta

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
> Di solito sarà necessario modificare il codice HTML della pagina e fare alcuni test in locale (magari usando un server Apache) **finché non ottieni il risultato desiderato.** Poi incolla quel codice HTML nel box.\
> Nota che se hai bisogno di **usare risorse statiche** per l'HTML (ad esempio alcune pagine CSS e JS) puoi salvarle in _**/opt/gophish/static/endpoint**_ e poi accedervi da _**/static/\<filename>**_

> [!TIP]
> Per la redirection potresti **reindirizzare gli utenti alla pagina principale legittima** della vittima, oppure reindirizzarli a _/static/migration.html_ per esempio, mettere una **spinning wheel (**[**https://loading.io/**](https://loading.io)**) per 5 secondi e poi indicare che il processo è stato completato con successo**.

### Users & Groups

- Imposta un nome
- **Importa i dati** (nota che per usare il template di esempio hai bisogno del firstname, last name e email address di ogni utente)

![](<../../images/image (163).png>)

### Campaign

Infine, crea una campaign selezionando un nome, l'email template, la landing page, l'URL, il sending profile e il group. Nota che l'URL sarà il link inviato alle vittime

Nota che il **Sending Profile permette di inviare un'email di test per vedere come apparirà l'email di phishing finale**:

![](<../../images/image (192).png>)

> [!TIP]
> Raccomando di **inviare le email di test agli indirizzi 10min mails** per evitare di essere blacklistati durante i test.

Una volta che tutto è pronto, lancia semplicemente la campaign!

## Website Cloning

Se per qualsiasi motivo vuoi clonare il sito web controlla la seguente pagina:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In alcuni phishing assessment (principalmente per Red Teams) potresti voler anche **inviare file contenenti qualche tipo di backdoor** (magari un C2 o magari qualcosa che scatti solo un'autenticazione).\
Guarda la seguente pagina per alcuni esempi:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attacco precedente è piuttosto efficace perché stai fingendo un vero sito web e raccogliendo le informazioni inserite dall'utente. Sfortunatamente, se l'utente non inserisce la password corretta o se l'applicazione che hai falsificato è configurata con 2FA, **queste informazioni non ti permetteranno di impersonare l'utente ingannato**.

Qui entrano in gioco strumenti come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena). Questi strumenti ti permettono di generare un attacco MitM. Fondamentalmente, l'attacco funziona in questo modo:

1. Tu **impersoni il form di login** della pagina reale.
2. L'utente **invia** le sue **credentials** alla tua pagina falsa e lo strumento le inoltra alla pagina reale, **verificando se le credenziali funzionano**.
3. Se l'account è configurato con **2FA**, la pagina MitM chiederà il codice e una volta che **l'utente lo inserisce** lo strumento lo inoltrerà alla pagina reale.
4. Una volta che l'utente è autenticato tu (come attacker) avrai **catturato le credentials, il 2FA, il cookie e qualsiasi informazione** di ogni interazione mentre lo strumento sta eseguendo il MitM.

### Via VNC

E se invece di **inviare la vittima a una pagina malevola** con lo stesso aspetto dell'originale, la inviassi a una **sessione VNC con un browser connesso alla pagina reale**? Saresti in grado di vedere cosa fa, rubare la password, l'MFA usata, i cookie...\
Puoi farlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Ovviamente uno dei modi migliori per sapere se sei stato scoperto è **cercare il tuo dominio nelle blacklists**. Se compare elencato, in qualche modo il tuo dominio è stato rilevato come sospetto.\
Un modo semplice per verificare se il tuo dominio appare in qualche blacklist è usare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, ci sono altri modi per capire se la vittima sta **attivamente cercando attività di phishing sospette nel mondo reale** come spiegato in:


{{#ref}}
detecting-phising.md
{{#endref}}

Puoi **acquistare un dominio con un nome molto simile** al dominio della vittima **e/o generare un certificato** per un **subdomain** di un dominio controllato da te **contenente** la **keyword** del dominio della vittima. Se la **vittima** effettua qualsiasi tipo di **DNS o HTTP interaction** con essi, saprai che **sta attivamente cercando** domini sospetti e dovrai essere molto stealth.

### Evaluate the phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious) per valutare se la tua email finirà nella cartella spam o se verrà bloccata o avrà successo.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Gli intrusion set moderni sempre più spesso saltano completamente le email lure e **mirano direttamente al service-desk / identity-recovery workflow** per sconfiggere l'MFA. L'attacco è totalmente "living-off-the-land": una volta che l'operatore possiede credenziali valide pivotano con strumenti amministrativi integrati – non è richiesto malware.

### Attack flow
1. Recon della vittima
* Raccogliere dettagli personali & aziendali da LinkedIn, data breaches, GitHub pubblico, ecc.
* Identificare identità ad alto valore (executives, IT, finance) e enumerare il **processo esatto di help-desk** per il reset di password / MFA.
2. Social engineering in tempo reale
* Telefonare, usare Teams o chat con l'help-desk impersonando l'obiettivo (spesso con **spoofed caller-ID** o **voce clonata**).
* Fornire le PII raccolte in precedenza per superare la verifica basata sulla conoscenza.
* Convincere l'agente a **resettare il secret MFA** o a eseguire un **SIM-swap** su un numero mobile registrato.
3. Azioni immediate post-accesso (≤60 min nei casi reali)
* Stabilire un foothold tramite qualsiasi web SSO portal.
* Enumerare AD / AzureAD con strumenti built-in (senza lasciare binari):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Movimento laterale con **WMI**, **PsExec**, o agenti legittimi **RMM** già whitelisted nell'ambiente.

### Detection & Mitigation
* Tratta il recovery dell'identità tramite help-desk come un'operazione **privilegiata** – richiedi step-up auth & approvazione del manager.
* Deploya regole **Identity Threat Detection & Response (ITDR)** / **UEBA** che allertino su:
* Metodo MFA cambiato + autenticazione da nuovo dispositivo / geo.
* Immediata elevazione dello stesso principal (user-→-admin).
* Registra le chiamate dell'help-desk e applica un **call-back a un numero già registrato** prima di qualsiasi reset.
* Implementa **Just-In-Time (JIT) / Privileged Access** in modo che gli account appena resettati non ereditino automaticamente token ad alto privilegio.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
I gruppi commodity compensano il costo delle operazioni high-touch con attacchi di massa che trasformano **search engines & ad networks nel canale di distribuzione**.

1. **SEO poisoning / malvertising** spinge un risultato falso come `chromium-update[.]site` in cima agli annunci di ricerca.
2. La vittima scarica un piccolo **first-stage loader** (spesso JS/HTA/ISO). Esempi osservati da Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Il loader esfiltra cookie del browser + credential DBs, poi scarica un **silent loader** che decide – *in tempo reale* – se distribuire:
* RAT (ad es. AsyncRAT, RustDesk)
* ransomware / wiper
* componente di persistence (registry Run key + scheduled task)

### Hardening tips
* Bloccare domini appena registrati & applicare **Advanced DNS / URL Filtering** sia sugli *search-ads* sia sulle email.
* Limitare l'installazione di software a pacchetti MSI firmati / Store, negare l'esecuzione di `HTA`, `ISO`, `VBS` tramite policy.
* Monitorare per processi figli dei browser che aprono installer:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Cacciare gli LOLBins spesso abusati dai first-stage loaders (es. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Gli attacker ora concatenano **LLM & voice-clone APIs** per lure completamente personalizzati e interazione in tempo reale.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Aggiungere **dynamic banners** che evidenziano messaggi inviati da automation non attendibili (tramite anomalie ARC/DKIM).  
• Deployare **voice-biometric challenge phrases** per richieste telefoniche ad alto rischio.  
• Simulare continuamente lure generati da AI nei programmi di awareness – i template statici sono obsoleti.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Oltre al classico push-bombing, gli operatori semplicemente **forzano una nuova registrazione MFA** durante la chiamata all'help-desk, annullando il token esistente dell'utente. Qualsiasi successiva richiesta di login apparirà legittima per la vittima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitorare gli eventi AzureAD/AWS/Okta in cui **`deleteMFA` + `addMFA`** si verificano **entro pochi minuti dallo stesso IP**.



## Clipboard Hijacking / Pastejacking

Gli attaccanti possono copiare silenziosamente comandi malevoli negli appunti della vittima da una pagina web compromessa o typosquatted e poi indurre l'utente a incollarli dentro **Win + R**, **Win + X** o una finestra del terminale, eseguendo codice arbitrario senza alcun download o allegato.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Gli operatori sempre più frequentemente pongono i loro flussi di phishing dietro un semplice controllo del dispositivo, così i crawler desktop non raggiungono mai le pagine finali. Un modello comune è uno script minimale che verifica se il DOM è touch-capable e invia il risultato a un endpoint del server; i client non-mobile ricevono HTTP 500 (o una pagina vuota), mentre agli utenti mobile viene servito il flusso completo.

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
- Accepts `POST /detect {"is_mobile":true|false}`.
- Restituisce 500 (o un placeholder) alle GET successive quando `is_mobile=false`; serve il phishing solo se `true`.

Hunting e euristiche di rilevamento:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: sequenza di `GET /static/detect_device.js` → `POST /detect` → HTTP 500 per non‑mobile; i percorsi legittimi per vittime su dispositivi mobili restituiscono 200 con HTML/JS successivo.
- Bloccare o esaminare con attenzione le pagine che condizionano il contenuto esclusivamente su `ontouchstart` o controlli del dispositivo simili.

Suggerimenti di difesa:
- Eseguire i crawler con fingerprint simili a dispositivi mobili e JS abilitato per rivelare contenuti gateati.
- Segnalare risposte 500 sospette dopo `POST /detect` su domini di recente registrazione.

## Riferimenti

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
