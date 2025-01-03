# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Riconoscere la vittima
1. Selezionare il **dominio della vittima**.
2. Eseguire alcune enumerazioni web di base **cercando portali di accesso** utilizzati dalla vittima e **decidere** quale impersonare.
3. Utilizzare alcune **OSINT** per **trovare email**.
2. Preparare l'ambiente
1. **Acquistare il dominio** che si intende utilizzare per la valutazione di phishing
2. **Configurare il servizio email** relativi record (SPF, DMARC, DKIM, rDNS)
3. Configurare il VPS con **gophish**
3. Preparare la campagna
1. Preparare il **modello di email**
2. Preparare la **pagina web** per rubare le credenziali
4. Lanciare la campagna!

## Generare nomi di dominio simili o acquistare un dominio affidabile

### Tecniche di Variazione del Nome di Dominio

- **Parola chiave**: Il nome di dominio **contiene** una **parola chiave** importante del dominio originale (es., zelster.com-management.com).
- **sottodominio con trattino**: Cambiare il **punto in un trattino** di un sottodominio (es., www-zelster.com).
- **Nuovo TLD**: Stesso dominio utilizzando un **nuovo TLD** (es., zelster.org)
- **Omo-glyph**: **Sostituisce** una lettera nel nome di dominio con **lettere che sembrano simili** (es., zelfser.com).
- **Trasposizione:** **Scambia due lettere** all'interno del nome di dominio (es., zelsetr.com).
- **Singolarizzazione/Pluralizzazione**: Aggiunge o rimuove “s” alla fine del nome di dominio (es., zeltsers.com).
- **Omissione**: **Rimuove una** delle lettere dal nome di dominio (es., zelser.com).
- **Ripetizione:** **Ripete una** delle lettere nel nome di dominio (es., zeltsser.com).
- **Sostituzione**: Come l'omo-glyph ma meno furtivo. Sostituisce una delle lettere nel nome di dominio, forse con una lettera vicina alla lettera originale sulla tastiera (es., zektser.com).
- **Sottodominio**: Introduce un **punto** all'interno del nome di dominio (es., ze.lster.com).
- **Inserimento**: **Inserisce una lettera** nel nome di dominio (es., zerltser.com).
- **Punto mancante**: Aggiunge il TLD al nome di dominio. (es., zelstercom.com)

**Strumenti Automatici**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Siti Web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

C'è una **possibilità che uno dei bit memorizzati o in comunicazione possa essere automaticamente invertito** a causa di vari fattori come flare solari, raggi cosmici o errori hardware.

Quando questo concetto è **applicato alle richieste DNS**, è possibile che il **dominio ricevuto dal server DNS** non sia lo stesso del dominio inizialmente richiesto.

Ad esempio, una singola modifica di bit nel dominio "windows.com" può cambiarlo in "windnws.com."

Gli attaccanti possono **sfruttare questo registrando più domini con bit-flipping** che sono simili al dominio della vittima. La loro intenzione è reindirizzare gli utenti legittimi alla propria infrastruttura.

Per ulteriori informazioni leggi [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Acquistare un dominio affidabile

Puoi cercare in [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio scaduto che potresti utilizzare.\
Per assicurarti che il dominio scaduto che stai per acquistare **abbia già un buon SEO**, puoi cercare come è categorizzato in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Scoprire Email

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuito)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratuito)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Per **scoprire di più** indirizzi email validi o **verificare quelli** che hai già scoperto, puoi controllare se puoi forzare in modo brutale i server smtp della vittima. [Scopri come verificare/scoprire indirizzi email qui](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Inoltre, non dimenticare che se gli utenti utilizzano **qualunque portale web per accedere alle loro email**, puoi controllare se è vulnerabile a **forza bruta del nome utente**, ed esplorare la vulnerabilità se possibile.

## Configurare GoPhish

### Installazione

Puoi scaricarlo da [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Scarica e decomprimi all'interno di `/opt/gophish` ed esegui `/opt/gophish/gophish`\
Ti verrà fornita una password per l'utente admin sulla porta 3333 nell'output. Pertanto, accedi a quella porta e utilizza quelle credenziali per cambiare la password dell'amministratore. Potresti dover tunnelare quella porta a locale:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configurazione

**Configurazione del certificato TLS**

Prima di questo passaggio dovresti **aver già acquistato il dominio** che intendi utilizzare e deve **puntare** all'**IP del VPS** dove stai configurando **gophish**.
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
**Configurazione della posta**

Inizia installando: `apt-get install postfix`

Poi aggiungi il dominio ai seguenti file:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Cambia anche i valori delle seguenti variabili all'interno di /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Infine modifica i file **`/etc/hostname`** e **`/etc/mailname`** con il tuo nome di dominio e **riavvia il tuo VPS.**

Ora, crea un **record A DNS** di `mail.<domain>` che punta all'**indirizzo IP** del VPS e un **record MX DNS** che punta a `mail.<domain>`

Ora testiamo l'invio di un'email:
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
## Configurazione del server di posta e del dominio

### Aspetta e sii legittimo

Più un dominio è vecchio, meno è probabile che venga catturato come spam. Quindi dovresti aspettare il più a lungo possibile (almeno 1 settimana) prima della valutazione di phishing. Inoltre, se metti una pagina su un settore reputazionale, la reputazione ottenuta sarà migliore.

Nota che anche se devi aspettare una settimana, puoi finire di configurare tutto ora.

### Configura il record DNS inverso (rDNS)

Imposta un record rDNS (PTR) che risolve l'indirizzo IP del VPS nel nome di dominio.

### Record Sender Policy Framework (SPF)

Devi **configurare un record SPF per il nuovo dominio**. Se non sai cos'è un record SPF [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/#spf).

Puoi usare [https://www.spfwizard.net/](https://www.spfwizard.net) per generare la tua politica SPF (usa l'IP della macchina VPS)

![](<../../images/image (1037).png>)

Questo è il contenuto che deve essere impostato all'interno di un record TXT all'interno del dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Record di Autenticazione, Reporting e Conformità dei Messaggi Basato su Dominio (DMARC)

Devi **configurare un record DMARC per il nuovo dominio**. Se non sai cos'è un record DMARC [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Devi creare un nuovo record DNS TXT che punti al nome host `_dmarc.<domain>` con il seguente contenuto:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Devi **configurare un DKIM per il nuovo dominio**. Se non sai cos'è un record DMARC [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/#dkim).

Questo tutorial si basa su: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!NOTE]
> Devi concatenare entrambi i valori B64 che genera la chiave DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testa il punteggio della tua configurazione email

Puoi farlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Basta accedere alla pagina e inviare un'email all'indirizzo che ti forniscono:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Puoi anche **controllare la tua configurazione email** inviando un'email a `check-auth@verifier.port25.com` e **leggendo la risposta** (per questo dovrai **aprire** la porta **25** e vedere la risposta nel file _/var/mail/root_ se invii l'email come root).\
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
Puoi anche inviare **un messaggio a un Gmail sotto il tuo controllo** e controllare le **intestazioni dell'email** nella tua casella di posta Gmail, `dkim=pass` dovrebbe essere presente nel campo di intestazione `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Rimozione dalla Blacklist di Spamhouse

La pagina [www.mail-tester.com](https://www.mail-tester.com) può indicarti se il tuo dominio è bloccato da spamhouse. Puoi richiedere la rimozione del tuo dominio/IP su: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Rimozione dalla Blacklist di Microsoft

Puoi richiedere la rimozione del tuo dominio/IP su [https://sender.office.com/](https://sender.office.com).

## Crea e Lancia una Campagna GoPhish

### Profilo di Invio

- Imposta un **nome per identificare** il profilo del mittente
- Decidi da quale account invierai le email di phishing. Suggerimenti: _noreply, support, servicedesk, salesforce..._
- Puoi lasciare vuoti il nome utente e la password, ma assicurati di selezionare Ignora Errori di Certificato

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!NOTE]
> È consigliato utilizzare la funzionalità "**Invia Email di Test**" per verificare che tutto funzioni.\
> Ti consiglio di **inviare le email di test a indirizzi 10min** per evitare di essere inseriti nella blacklist durante i test.

### Modello di Email

- Imposta un **nome per identificare** il modello
- Poi scrivi un **oggetto** (niente di strano, solo qualcosa che ti aspetteresti di leggere in una email normale)
- Assicurati di aver selezionato "**Aggiungi Immagine di Tracciamento**"
- Scrivi il **modello di email** (puoi usare variabili come nel seguente esempio):
```markup
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
Nota che **per aumentare la credibilità dell'email**, è consigliato utilizzare qualche firma da un'email del cliente. Suggerimenti:

- Invia un'email a un **indirizzo inesistente** e controlla se la risposta ha qualche firma.
- Cerca **email pubbliche** come info@ex.com o press@ex.com o public@ex.com e invia loro un'email e aspetta la risposta.
- Prova a contattare **qualche email valida scoperta** e aspetta la risposta.

![](<../../images/image (80).png>)

> [!NOTE]
> Il Modello di Email consente anche di **allegare file da inviare**. Se desideri anche rubare le sfide NTLM utilizzando alcuni file/documenti appositamente creati [leggi questa pagina](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Scrivi un **nome**
- **Scrivi il codice HTML** della pagina web. Nota che puoi **importare** pagine web.
- Seleziona **Cattura Dati Inviati** e **Cattura Passwords**
- Imposta un **reindirizzamento**

![](<../../images/image (826).png>)

> [!NOTE]
> Di solito dovrai modificare il codice HTML della pagina e fare alcuni test in locale (magari usando un server Apache) **fino a quando non ti piacciono i risultati.** Poi, scrivi quel codice HTML nella casella.\
> Nota che se hai bisogno di **utilizzare alcune risorse statiche** per l'HTML (magari alcune pagine CSS e JS) puoi salvarle in _**/opt/gophish/static/endpoint**_ e poi accedervi da _**/static/\<filename>**_

> [!NOTE]
> Per il reindirizzamento potresti **reindirizzare gli utenti alla legittima pagina principale** della vittima, o reindirizzarli a _/static/migration.html_ per esempio, mettere qualche **ruota che gira (**[**https://loading.io/**](https://loading.io)**) per 5 secondi e poi indicare che il processo è stato completato con successo**.

### Utenti e Gruppi

- Imposta un nome
- **Importa i dati** (nota che per utilizzare il modello per l'esempio hai bisogno del nome, cognome e indirizzo email di ogni utente)

![](<../../images/image (163).png>)

### Campagna

Infine, crea una campagna selezionando un nome, il modello di email, la landing page, l'URL, il profilo di invio e il gruppo. Nota che l'URL sarà il link inviato alle vittime.

Nota che il **Profilo di Invio consente di inviare un'email di prova per vedere come apparirà l'email di phishing finale**:

![](<../../images/image (192).png>)

> [!NOTE]
> Ti consiglio di **inviare le email di prova a indirizzi di 10min mail** per evitare di essere inserito in blacklist durante i test.

Una volta che tutto è pronto, lancia semplicemente la campagna!

## Clonazione del Sito Web

Se per qualche motivo desideri clonare il sito web, controlla la seguente pagina:

{{#ref}}
clone-a-website.md
{{#endref}}

## Documenti e File Backdoor

In alcune valutazioni di phishing (principalmente per Red Teams) vorrai anche **inviare file contenenti qualche tipo di backdoor** (magari un C2 o magari solo qualcosa che attivi un'autenticazione).\
Controlla la seguente pagina per alcuni esempi:

{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attacco precedente è piuttosto astuto poiché stai falsificando un sito web reale e raccogliendo le informazioni fornite dall'utente. Sfortunatamente, se l'utente non ha inserito la password corretta o se l'applicazione che hai falsificato è configurata con 2FA, **queste informazioni non ti permetteranno di impersonare l'utente ingannato**.

Qui è dove strumenti come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) sono utili. Questo strumento ti permetterà di generare un attacco simile a MitM. Fondamentalmente, gli attacchi funzionano nel seguente modo:

1. Tu **impersoni il modulo di accesso** della pagina web reale.
2. L'utente **invia** le sue **credenziali** alla tua pagina falsa e lo strumento le invia alla pagina web reale, **controllando se le credenziali funzionano**.
3. Se l'account è configurato con **2FA**, la pagina MitM chiederà di inserirlo e una volta che l'**utente lo introduce**, lo strumento lo invierà alla pagina web reale.
4. Una volta che l'utente è autenticato, tu (come attaccante) avrai **catturato le credenziali, il 2FA, il cookie e qualsiasi informazione** di ogni interazione mentre lo strumento sta eseguendo un MitM.

### Via VNC

E se invece di **inviare la vittima a una pagina malevola** con lo stesso aspetto di quella originale, la invii a una **sessione VNC con un browser connesso alla pagina web reale**? Sarai in grado di vedere cosa fa, rubare la password, il MFA utilizzato, i cookie...\
Puoi farlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Rilevare la rilevazione

Ovviamente uno dei migliori modi per sapere se sei stato scoperto è **cercare il tuo dominio all'interno delle blacklist**. Se appare elencato, in qualche modo il tuo dominio è stato rilevato come sospetto.\
Un modo semplice per controllare se il tuo dominio appare in qualche blacklist è utilizzare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, ci sono altri modi per sapere se la vittima è **attivamente alla ricerca di attività di phishing sospette nel mondo** come spiegato in:

{{#ref}}
detecting-phising.md
{{#endref}}

Puoi **comprare un dominio con un nome molto simile** a quello del dominio della vittima **e/o generare un certificato** per un **sottodominio** di un dominio controllato da te **contenente** la **parola chiave** del dominio della vittima. Se la **vittima** esegue qualche tipo di **interazione DNS o HTTP** con essi, saprai che **sta cercando attivamente** domini sospetti e dovrai essere molto furtivo.

### Valutare il phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious) per valutare se la tua email finirà nella cartella spam o se verrà bloccata o avrà successo.

## Riferimenti

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{{#include ../../banners/hacktricks-training.md}}
