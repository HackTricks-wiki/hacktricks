# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Recon the victim
1. Seleziona il **dominio della vittima**.
2. Esegui una enumerazione web di base **cercando portali di login** usati dalla vittima e **decidi** quale impersonare.
3. Usa OSINT per **trovare indirizzi email**.
2. Prepara l'ambiente
1. **Compra il dominio** che userai per la valutazione di phishing
2. **Configura i record** correlati al servizio email (SPF, DMARC, DKIM, rDNS)
3. Configura il VPS con **gophish**
3. Prepara la campagna
1. Prepara il **template dell'email**
2. Prepara la **pagina web** per rubare le credenziali
4. Lancia la campagna!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Il nome di dominio **contiene** una parola chiave importante del dominio originale (es., zelster.com-management.com).
- **hypened subdomain**: Sostituisci il **punto con un trattino** in un sottodominio (es., www-zelster.com).
- **New TLD**: Stesso dominio usando una **nuova TLD** (es., zelster.org)
- **Homoglyph**: Sostituisce una lettera nel nome di dominio con **caratteri dall'aspetto simile** (es., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Scambia due lettere all'interno del nome di dominio (es., zelsetr.com).
- **Singularization/Pluralization**: Aggiunge o rimuove una “s” alla fine del nome di dominio (es., zeltsers.com).
- **Omission**: Rimuove una delle lettere dal nome di dominio (es., zelser.com).
- **Repetition:** Ripete una delle lettere nel nome di dominio (es., zeltsser.com).
- **Replacement**: Simile all'homoglyph ma meno stealthy. Sostituisce una delle lettere nel nome di dominio, magari con una lettera vicina sulla tastiera (es., zektser.com).
- **Subdomained**: Introduce un **punto** all'interno del nome di dominio (es., ze.lster.com).
- **Insertion**: Inserisce una lettera nel nome di dominio (es., zerltser.com).
- **Missing dot**: Aggiunge la TLD direttamente al nome di dominio. (es., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Esiste la **possibilità che uno o più bit memorizzati o in comunicazione vengano invertiti automaticamente** a causa di vari fattori come brillamenti solari, raggi cosmici o errori hardware.

Quando questo concetto viene **applicato alle richieste DNS**, è possibile che il **dominio ricevuto dal server DNS** non sia lo stesso del dominio inizialmente richiesto.

Per esempio, una singola modifica di bit nel dominio "windows.com" può trasformarlo in "windnws.com."

Gli attacker possono **sfruttare questo registrando più domini bit-flipping** simili al dominio della vittima. L'intento è reindirizzare gli utenti legittimi alla propria infrastruttura.

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

Per **scoprire più** indirizzi email validi o **verificare quelli** che hai già scoperto puoi controllare se puoi effettuare username brute force contro i server smtp della vittima. [Scopri come verificare/scoprire indirizzi email qui](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Inoltre, non dimenticare che se gli utenti usano **un web portal per accedere alle loro mail**, puoi verificare se è vulnerabile a username brute force e sfruttare la vulnerabilità se possibile.

## Configuring GoPhish

### Installation

Puoi scaricarlo da [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Scaricalo e decomprimilo dentro `/opt/gophish` ed esegui `/opt/gophish/gophish`\
Ti verrà fornita una password per l'utente admin sulla porta 3333 nell'output. Quindi, accedi a quella porta e usa quelle credenziali per cambiare la password admin. Potrebbe essere necessario fare il tunnel di quella porta in locale:
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
**Configurazione della posta**

Inizia l'installazione: `apt-get install postfix`

Poi aggiungi il dominio ai seguenti file:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifica anche i valori delle seguenti variabili dentro /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Infine modifica i file **`/etc/hostname`** e **`/etc/mailname`** con il tuo nome di dominio e **riavvia il tuo VPS.**

Ora, crea un **DNS A record** per `mail.<domain>` che punti all'**indirizzo IP** del VPS e un record **DNS MX** che punti a `mail.<domain>`

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
**Configurare il servizio gophish**

Per creare il servizio gophish in modo che possa essere avviato automaticamente e gestito come servizio, è possibile creare il file `/etc/init.d/gophish` con il seguente contenuto:
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
## Configurazione del server mail e del dominio

### Aspetta e sii legittimo

Più un dominio è vecchio, meno è probabile che venga classificato come spam. Dovresti quindi attendere il più a lungo possibile (almeno 1 settimana) prima del phishing assessment. Inoltre, se pubblichi una pagina relativa a un settore con buona reputazione, la reputazione ottenuta sarà migliore.

Nota che, anche se devi aspettare una settimana, puoi comunque completare ora tutta la configurazione.

### Configura il record Reverse DNS (rDNS)

Imposta un record rDNS (PTR) che risolva l'indirizzo IP del VPS nel nome di dominio.

### Sender Policy Framework (SPF) Record

Devi **configurare un record SPF per il nuovo dominio**. Se non sai cos'è un record SPF [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puoi usare [https://www.spfwizard.net/](https://www.spfwizard.net) per generare la tua policy SPF (usa l'IP della macchina VPS)

![](<../../images/image (1037).png>)

Questo è il contenuto da impostare in un record TXT del dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Record DMARC (Autenticazione dei messaggi basata sul dominio, reporting e conformità)

Devi **configurare un record DMARC per il nuovo dominio**. Se non sai cos'è un record DMARC [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Devi creare un nuovo record DNS TXT che punti al nome host `_dmarc.<domain>` con il seguente contenuto:
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

### Testa il punteggio della configurazione della tua email

Puoi farlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Basta accedere alla pagina e inviare un'email all'indirizzo che ti indicano:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Puoi anche **controllare la configurazione della tua email** inviando un'email a `check-auth@verifier.port25.com` e **leggendo la risposta** (per questo dovrai **aprire** la porta **25** e vedere la risposta nel file _/var/mail/root_ se invii l'email come root).\
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
Puoi anche inviare **un messaggio a un account Gmail sotto il tuo controllo**, e controllare le **intestazioni dell'email** nella tua casella Gmail: `dkim=pass` dovrebbe essere presente nel campo header `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Rimozione dalla Spamhouse Blacklist

La pagina [www.mail-tester.com](https://www.mail-tester.com) può indicarti se il tuo dominio è bloccato da spamhouse. Puoi richiedere la rimozione del tuo dominio/IP su: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Rimozione dalla Microsoft Blacklist

​​Puoi richiedere la rimozione del tuo dominio/IP su [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Inserisci un **nome per identificare** il profilo mittente
- Decidi da quale account invierai le email di phishing. Suggerimenti: _noreply, support, servicedesk, salesforce..._
- Puoi lasciare vuoti username e password, ma assicurati di selezionare Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> È consigliato utilizzare la funzionalità "**Send Test Email**" per verificare che tutto funzioni.\
> Consiglio di **inviare le test email a 10min mails addresses** per evitare di finire in blacklist durante i test.

### Email Template

- Inserisci un **nome per identificare** il template
- Poi scrivi un **subject** (niente di strano, qualcosa che ci si aspetterebbe di leggere in una email normale)
- Assicurati di aver selezionato "**Add Tracking Image**"
- Scrivi il **email template** (puoi usare variabili come nel seguente esempio):
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
Nota che **per aumentare la credibilità dell'email** è raccomandato usare qualche firma presa da un'email del cliente. Suggerimenti:

- Invia un'email a un **indirizzo inesistente** e verifica se la risposta contiene una firma.
- Cerca **email pubbliche** come info@ex.com o press@ex.com o public@ex.com e invia loro un'email aspettando la risposta.
- Prova a contattare **un indirizzo valido scoperto** e attendi la risposta

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Inserisci un **nome**
- **Scrivi il codice HTML** della pagina web. Nota che puoi **importare** pagine web.
- Seleziona **Capture Submitted Data** e **Capture Passwords**
- Imposta una **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Solitamente dovrai modificare il codice HTML della pagina e fare dei test in locale (magari usando un server Apache) **fino a quando non sei soddisfatto del risultato.** Poi, incolla quel codice HTML nella casella.\
> Nota che se hai bisogno di **utilizzare risorse statiche** per l'HTML (per esempio CSS o JS) puoi salvarle in _**/opt/gophish/static/endpoint**_ e poi accedervi da _**/static/\<filename>**_

> [!TIP]
> Per la redirection potresti **reindirizzare gli utenti alla pagina principale legittima** della vittima, oppure reindirizzarli a _/static/migration.html_ ad esempio, mettere una **ruota che gira (**[**https://loading.io/**](https://loading.io)**) per 5 secondi e poi indicare che il processo è stato completato con successo**.

### Users & Groups

- Imposta un nome
- **Importa i dati** (nota che per usare il template di esempio hai bisogno del firstname, last name e email address di ogni utente)

![](<../../images/image (163).png>)

### Campaign

Infine, crea una campagna selezionando un nome, l'email template, la landing page, l'URL, il sending profile e il gruppo. Nota che l'URL sarà il link inviato alle vittime

Nota che il **Sending Profile permette di inviare un'email di test per vedere come apparirà l'email di phishing finale**:

![](<../../images/image (192).png>)

> [!TIP]
> Raccomando di **inviare le email di test a indirizzi 10min mails** per evitare di essere inseriti in blacklist durante i test.

Una volta pronto tutto, lancia la campagna!

## Clonazione del sito web

Se per qualsiasi motivo vuoi clonare il sito web consulta la seguente pagina:


{{#ref}}
clone-a-website.md
{{#endref}}

## File e documenti con backdoor

In alcune valutazioni di phishing (soprattutto per Red Teams) vorrai anche **inviare file che contengano una qualche backdoor** (magari un C2 o magari solo qualcosa che scateni un'autenticazione).\
Dai un'occhiata alla seguente pagina per alcuni esempi:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attacco precedente è piuttosto efficace perché stai falsificando un sito reale e raccogliendo le informazioni inserite dall'utente. Sfortunatamente, se l'utente non inserisce la password corretta o se l'applicazione che hai falsificato è configurata con 2FA, **queste informazioni non ti permetteranno di impersonare l'utente raggirato**.

Qui entrano in gioco strumenti come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena). Questi strumenti permettono di generare un attacco MitM. Fondamentalmente, l'attacco funziona così:

1. Tu **falsifichi il form di login** della pagina reale.
2. L'utente **invia** le sue **credenziali** alla tua pagina fake e lo strumento le invia alla pagina reale, **verificando se le credenziali funzionano**.
3. Se l'account è configurato con **2FA**, la pagina MitM richiederà il codice e una volta che **l'utente lo inserisce** lo strumento lo inoltrerà alla pagina web reale.
4. Una volta che l'utente è autenticato tu (come attaccante) avrai **catturato le credenziali, la 2FA, il cookie e qualsiasi informazione** di ogni interazione mentre lo strumento esegue il MitM.

### Via VNC

E se invece di **inviare la vittima a una pagina malevola** dall'aspetto identico all'originale, la mandi a una **sessione VNC con un browser connesso alla pagina reale**? Potrai vedere cosa fa, rubare la password, l'MFA usata, i cookie...\
Puoi farlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Rilevare di essere stati scoperti

Ovviamente uno dei modi migliori per sapere se sei stato beccato è **cercare il tuo dominio nelle blacklist**. Se appare elencato, in qualche modo il tuo dominio è stato rilevato come sospetto.\
Un modo semplice per verificare se il tuo dominio appare in qualche blacklist è usare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, ci sono altri modi per capire se la vittima sta **attivamente cercando attività di phishing sospette** in circolazione, come spiegato in:


{{#ref}}
detecting-phising.md
{{#endref}}

Puoi **comprare un dominio con un nome molto simile** a quello della vittima **e/o generare un certificato** per un **sottodominio** di un dominio controllato da te **contenente** la **parola chiave** del dominio della vittima. Se la **vittima** effettua qualsiasi tipo di **interazione DNS o HTTP** con essi, saprai che **sta cercando attivamente** domini sospetti e dovrai essere molto stealth.

### Valutare il phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious) per valutare se la tua email finirà nella cartella spam o se verrà bloccata o avrà successo.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

I moderni set di intrusione sempre più spesso evitano completamente gli esche via email e **mirano direttamente al servizio di help-desk / al workflow di recovery dell'identità** per bypassare l'MFA. L'attacco è totalmente "living-off-the-land": una volta che l'operatore ottiene credenziali valide pivotano con strumenti amministrativi integrati – non è necessario malware.

### Flusso dell'attacco
1. Recon sulla vittima
* Raccogli dettagli personali e aziendali da LinkedIn, breach di dati, GitHub pubblico, ecc.
* Identifica identità ad alto valore (dirigenti, IT, finance) e enumera il **preciso processo di help-desk** per il reset di password / MFA.
2. Social engineering in tempo reale
* Chiama, contatta via Teams o chat l'help-desk impersonando la vittima (spesso con **spoofed caller-ID** o **voce clonata**).
* Fornisci i PII raccolti in precedenza per superare la verifica basata sulla conoscenza.
* Convincere l'agente a **resettare il secret MFA** o eseguire un **SIM-swap** su un numero mobile registrato.
3. Azioni immediate post-accesso (≤60 min in casi reali)
* Stabilisci un foothold tramite qualsiasi portale web SSO.
* Enumera AD / AzureAD con strumenti integrati (nessun binary lasciato):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Movimento laterale con **WMI**, **PsExec**, o agenti legittimi **RMM** già nella whitelist dell'ambiente.

### Rilevazione e mitigazione
* Tratta il recovery dell'identità tramite help-desk come un'**operazione privilegiata** – richiedi step-up auth e approvazione del manager.
* Distribuisci regole **Identity Threat Detection & Response (ITDR)** / **UEBA** che generino alert su:
  * Metodo MFA cambiato + autenticazione da nuovo dispositivo / nuova geo.
  * Immediata elevazione dello stesso principal (user → admin).
* Registra le chiamate dell'help-desk e imposta un **call-back a un numero già registrato** prima di qualsiasi reset.
* Implementa **Just-In-Time (JIT) / Privileged Access** in modo che gli account appena resettati **non** ereditino automaticamente token ad alto privilegio.

---

## Inganno su larga scala – SEO Poisoning & campagne “ClickFix”
Gruppi commodity compensano il costo delle operazioni high-touch con attacchi di massa che trasformano **motori di ricerca & reti pubblicitarie nel canale di consegna**.

1. **SEO poisoning / malvertising** spinge un risultato falso come `chromium-update[.]site` tra i primi annunci di ricerca.
2. La vittima scarica un piccolo **first-stage loader** (spesso JS/HTA/ISO). Esempi osservati da Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Il loader esfiltra cookie del browser + database credenziali, poi scarica un **silent loader** che decide – *in tempo reale* – se distribuire:
* RAT (es. AsyncRAT, RustDesk)
* ransomware / wiper
* componente di persistenza (chiave Run del registro + scheduled task)

### Consigli per hardening
* Blocca i domini appena registrati e applica **Advanced DNS / URL Filtering** sia sugli *search-ads* sia sulle email.
* Restringi l'installazione di software a pacchetti MSI firmati / Store, nega l'esecuzione di `HTA`, `ISO`, `VBS` tramite policy.
* Monitora processi figli dei browser che aprono installer:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Caccia le LOLBins frequentemente abusate dai first-stage loader (es. `regsvr32`, `curl`, `mshta`).

---

## Operazioni di phishing potenziate dall'AI
Gli attaccanti ora concatenano **API LLM & voice-clone** per esche totalmente personalizzate e interazioni in tempo reale.

| Layer | Esempio d'uso da parte di un threat actor |
|-------|-------------------------------------------|
|Automazione|Generare e inviare >100k email / SMS con testi randomizzati & link di tracking.|
|AI generativa|Produrre email *one-off* che citano M&A pubblici, battute interne dai social; deep-fake della voce del CEO in una chiamata di callback.|
|AI agentica|Registrare domini autonomamente, scrape di intel open-source, creare mail di follow-up quando una vittima clicca ma non invia credenziali.|

**Difesa:**
• Aggiungi **banner dinamici** che evidenzino messaggi inviati da automazione non attendibile (via anomalie ARC/DKIM).  
• Distribuisci **frasi di challenge biometrica vocale** per richieste telefoniche ad alto rischio.  
• Simula continuamente esche generate da AI nei programmi di awareness – i template statici sono obsoleti.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Oltre al classico push-bombing, gli operatori semplicemente **forzano una nuova registrazione MFA** durante la chiamata con l'help-desk, azzerando il token esistente dell'utente. Qualsiasi prompt di login successivo apparirà legittimo alla vittima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitorare eventi di AzureAD/AWS/Okta in cui **`deleteMFA` + `addMFA`** si verificano **dallo stesso IP entro pochi minuti**.



## Clipboard Hijacking / Pastejacking

Gli attaccanti possono copiare silenziosamente comandi malevoli negli appunti (clipboard) della vittima da una pagina web compromessa o typosquatted e poi indurre l'utente a incollarli in **Win + R**, **Win + X** o in una finestra del terminale, eseguendo codice arbitrario senza alcun download o allegato.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## Riferimenti

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
