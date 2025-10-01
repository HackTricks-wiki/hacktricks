# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Metodología

1. Recon de la víctima
1. Selecciona el **dominio de la víctima**.
2. Realiza una enumeración web básica **buscando portales de inicio de sesión** usados por la víctima y **decide** cuál vas a **suplantar**.
3. Usa **OSINT** para **encontrar correos electrónicos**.
2. Prepara el entorno
1. **Compra el dominio** que vas a usar para la evaluación de phishing
2. **Configura los registros** relacionados con el servicio de correo (SPF, DMARC, DKIM, rDNS)
3. Configura el VPS con **gophish**
3. Prepara la campaña
1. Prepara la **plantilla de email**
2. Prepara la **página web** para robar las credenciales
4. ¡Lanza la campaña!

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
Para asegurarte de que el dominio expirado que vas a comprar **ya tenga buen SEO** puedes comprobar cómo está categorizado en:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Para **descubrir más** direcciones de correo válidas o **verificar las que** ya has encontrado, puedes comprobar si puedes hacer brute-force contra los servidores SMTP del objetivo. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Además, no olvides que si los usuarios usan **algún portal web para acceder a sus correos**, puedes comprobar si es vulnerable a **username brute force**, y explotar la vulnerabilidad si es posible.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
Se te proporcionará una contraseña para el usuario admin en el puerto 3333 en la salida. Por lo tanto, accede a ese puerto y usa esas credenciales para cambiar la contraseña del admin. Puede que necesites tunelar ese puerto a local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuración

**Configuración del certificado TLS**

Antes de este paso deberías haber **comprado ya el dominio** que vas a usar y debe estar **apuntando** a la **IP del VPS** donde estás configurando **gophish**.
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

Comienza instalando: `apt-get install postfix`

Luego añade el dominio a los siguientes archivos:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Cambia también los valores de las siguientes variables dentro de /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Finalmente modifica los archivos **`/etc/hostname`** y **`/etc/mailname`** con tu nombre de dominio y **reinicia tu VPS.**

Ahora, crea un **registro DNS A** de `mail.<domain>` que apunte a la **dirección IP** del VPS y un **registro DNS MX** que apunte a `mail.<domain>`

Ahora vamos a probar a enviar un correo:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuración de Gophish**

Detén la ejecución de gophish y vamos a configurarlo.\
Modifica `/opt/gophish/config.json` a lo siguiente (nota el uso de https):
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

Para crear el servicio gophish de modo que pueda iniciarse automáticamente y gestionarse como un servicio, puedes crear el archivo `/etc/init.d/gophish` con el siguiente contenido:
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
Termina de configurar el servicio y compruébalo haciendo:
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

Cuanto más antiguo sea un dominio, menos probable será que sea detectado como spam. Por tanto, debes esperar tanto tiempo como sea posible (al menos 1 semana) antes de la evaluación de phishing. Además, si pones una página relacionada con un sector con reputación, la reputación obtenida será mejor.

Ten en cuenta que, aunque tengas que esperar una semana, puedes terminar de configurar todo ahora.

### Configure Reverse DNS (rDNS) record

Configura un registro rDNS (PTR) que resuelva la dirección IP del VPS al nombre de dominio.

### Sender Policy Framework (SPF) Record

Debes **configurar un registro SPF para el nuevo dominio**. Si no sabes qué es un registro SPF [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puedes usar [https://www.spfwizard.net/](https://www.spfwizard.net) para generar tu política SPF (usa la IP de la máquina VPS)

![](<../../images/image (1037).png>)

Este es el contenido que debe establecerse dentro de un registro TXT en el dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro DMARC (Domain-based Message Authentication, Reporting & Conformance)

Debes **configurar un registro DMARC para el nuevo dominio**. Si no sabes qué es un registro DMARC [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Tienes que crear un nuevo registro DNS TXT apuntando el hostname `_dmarc.<domain>` con el siguiente contenido:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Debes **configurar un DKIM para el nuevo dominio**. Si no sabes qué es un registro DMARC [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Este tutorial se basa en: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Necesitas concatenar ambos valores B64 que genera la clave DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Prueba la puntuación de la configuración de tu correo electrónico

Puedes hacerlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Solo accede a la página y envía un correo a la dirección que te dan:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
También puedes **comprobar tu configuración de correo** enviando un correo a `check-auth@verifier.port25.com` y **leer la respuesta** (para esto necesitarás **abrir** el puerto **25** y ver la respuesta en el archivo _/var/mail/root_ si envías el correo como root).\
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
También puedes enviar un **mensaje a un Gmail bajo tu control**, y comprobar las **cabeceras del correo** en tu bandeja de entrada de Gmail, `dkim=pass` debería estar presente en el campo de cabecera `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Eliminación de la lista negra de Spamhouse

La página [www.mail-tester.com](https://www.mail-tester.com) puede indicarte si tu dominio está siendo bloqueado por Spamhouse. Puedes solicitar que tu dominio/IP sea eliminado en: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Eliminación de la lista negra de Microsoft

​​Puedes solicitar que tu dominio/IP sea eliminado en [https://sender.office.com/](https://sender.office.com).

## Crear & lanzar campaña de GoPhish

### Perfil de envío

- Asigna algún **nombre para identificar** el perfil del remitente
- Decide desde qué cuenta vas a enviar los emails de phishing. Sugerencias: _noreply, support, servicedesk, salesforce..._
- Puedes dejar en blanco el username y password, pero asegúrate de marcar Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> It's recommended to use the "**Send Test Email**" functionality to test that everything is working.\
> Recomiendo **enviar los correos de prueba a direcciones de 10min mails** para evitar ser listado en listas negras al hacer pruebas.

### Plantilla de correo

- Asigna algún **nombre para identificar** la plantilla
- Luego escribe un **subject** (nada extraño, simplemente algo que esperarías leer en un correo normal)
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
Tenga en cuenta que **para aumentar la credibilidad del correo electrónico**, se recomienda usar alguna firma de un email del cliente. Sugerencias:

- Enviar un email a una **dirección inexistente** y comprobar si la respuesta tiene alguna firma.
- Buscar **emails públicos** como info@ex.com o press@ex.com o public@ex.com y enviarles un correo y esperar la respuesta.
- Intentar contactar **algún email válido descubierto** y esperar la respuesta

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Página de destino

- Escribir un **nombre**
- **Escribir el código HTML** de la página web. Ten en cuenta que puedes **importar** páginas web.
- Marcar **Capture Submitted Data** y **Capture Passwords**
- Establecer una **redirección**

![](<../../images/image (826).png>)

> [!TIP]
> Normalmente necesitarás modificar el código HTML de la página y hacer algunas pruebas en local (quizá usando algún servidor Apache) **hasta que te guste el resultado.** Entonces, pega ese código HTML en el cuadro.\
> Ten en cuenta que si necesitas **usar recursos estáticos** para el HTML (por ejemplo CSS y JS) puedes guardarlos en _**/opt/gophish/static/endpoint**_ y luego acceder a ellos desde _**/static/\<filename>**_

> [!TIP]
> Para la redirección podrías **redirigir a los usuarios a la web legítima principal** de la víctima, o redirigirlos a _/static/migration.html_ por ejemplo, poner una **rueda giratoria (**[**https://loading.io/**](https://loading.io)**) durante 5 segundos y luego indicar que el proceso fue exitoso**.

### Usuarios & Grupos

- Establecer un nombre
- **Importar los datos** (ten en cuenta que para usar la plantilla en el ejemplo necesitas el firstname, last name y email address de cada usuario)

![](<../../images/image (163).png>)

### Campaña

Finalmente, crea una campaña seleccionando un nombre, la plantilla de email, la landing page, la URL, el Sending Profile y el grupo. Ten en cuenta que la URL será el enlace enviado a las víctimas

Ten en cuenta que el **Sending Profile permite enviar un email de prueba para ver cómo quedará el correo final de phishing**:

![](<../../images/image (192).png>)

> [!TIP]
> Recomendaría **enviar los correos de prueba a direcciones 10min mails** para evitar ser blacklistado mientras haces pruebas.

¡Una vez que todo esté listo, lanza la campaña!

## Website Cloning

Si por alguna razón quieres clonar el sitio web, consulta la siguiente página:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

En algunas evaluaciones de phishing (principalmente para Red Teams) también querrás **enviar archivos que contengan algún tipo de backdoor** (quizá un C2 o quizá algo que solo desencadene una autenticación).\
Consulta la siguiente página para algunos ejemplos:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

El ataque anterior es bastante ingenioso ya que estás falsificando un sitio real y recopilando la información que introduce el usuario. Desafortunadamente, si el usuario no introduce la contraseña correcta o si la aplicación que falsificaste está configurada con 2FA, **esa información no te permitirá suplantar al usuario engañado**.

Aquí es donde herramientas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) y [**muraena**](https://github.com/muraenateam/muraena) son útiles. Esta herramienta te permitirá generar un ataque tipo MitM. Básicamente, el ataque funciona de la siguiente manera:

1. Tú **suplantas el formulario de login** de la página real.
2. El usuario **envía** sus **credentials** a tu página falsa y la herramienta las reenvía a la página real, **comprobando si las credenciales funcionan**.
3. Si la cuenta está configurada con **2FA**, la página MitM pedirá el código y una vez que el **usuario lo introduce** la herramienta lo enviará a la página real.
4. Una vez que el usuario está autenticado tú (como atacante) habrás **capturado las credenciales, el 2FA, la cookie y cualquier información** de cada interacción mientras la herramienta realiza el MitM.

### Via VNC

¿Qué pasa si en lugar de **enviar a la víctima a una página maliciosa** con apariencia igual a la original, la envías a una **sesión VNC con un navegador conectado al sitio real**? Podrás ver lo que hace, robar la contraseña, el MFA usado, las cookies...\
Puedes hacer esto con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obviamente, una de las mejores maneras de saber si te han pillado es **buscar tu dominio en listas negras**. Si aparece listado, de alguna forma tu dominio fue detectado como sospechoso.\
Una forma fácil de comprobar si tu dominio aparece en alguna blacklist es usar [https://malwareworld.com/](https://malwareworld.com)

Sin embargo, hay otras formas de saber si la víctima está **buscando activamente actividad de phishing sospechosa en la red** como se explica en:


{{#ref}}
detecting-phising.md
{{#endref}}

Puedes **comprar un dominio con un nombre muy similar** al dominio de la víctima **y/o generar un certificado** para un **subdominio** de un dominio controlado por ti **que contenga** la **palabra clave** del dominio de la víctima. Si la **víctima** realiza cualquier tipo de interacción **DNS o HTTP** con ellos, sabrás que **está buscando activamente** dominios sospechosos y tendrás que ser muy sigiloso.

### Evaluar el phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious) para evaluar si tu email terminará en la carpeta de spam o si va a ser bloqueado o será exitoso.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Los conjuntos de intrusión modernos cada vez evitan totalmente los señuelos por email y **apuntan directamente al flujo de trabajo de service-desk / identity-recovery** para derrotar el MFA. El ataque es totalmente "living-off-the-land": una vez que el operador posee credenciales válidas pivota con herramientas administrativas integradas – no se requiere malware.

### Flujo de ataque
1. Recon de la víctima
* Recopilar detalles personales y corporativos de LinkedIn, breaches de datos, GitHub público, etc.
* Identificar identidades de alto valor (ejecutivos, IT, finanzas) y enumerar el **proceso exacto del help-desk** para reset de contraseña / MFA.
2. Ingeniería social en tiempo real
* Llamar por teléfono, Teams o chat al help-desk haciéndose pasar por el objetivo (a menudo con **spoofed caller-ID** o **voz clonada**).
* Proporcionar el PII previamente recopilado para pasar la verificación basada en conocimiento.
* Convencer al agente para que **reseteé el secreto MFA** o realice un **SIM-swap** en un número móvil registrado.
3. Acciones inmediatas post-acceso (≤60 min en casos reales)
* Establecer un foothold a través de cualquier portal web SSO.
* Enumerar AD / AzureAD con herramientas integradas (sin dejar binarios):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Movimiento lateral con **WMI**, **PsExec**, o agentes legítimos de **RMM** ya en lista blanca en el entorno.

### Detección & Mitigación
* Tratar la recuperación de identidad por help-desk como una **operación privilegiada** – requerir step-up auth y aprobación del manager.
* Desplegar reglas de **Identity Threat Detection & Response (ITDR)** / **UEBA** que alerten sobre:
* Método MFA cambiado + autenticación desde nuevo dispositivo / geolocalización.
* Elevación inmediata del mismo principal (user-→-admin).
* Grabar las llamadas al help-desk y exigir una **devolución de llamada a un número ya registrado** antes de cualquier reseteo.
* Implementar **Just-In-Time (JIT) / Privileged Access** para que las cuentas recién reseteadas **no** hereden automáticamente tokens de alto privilegio.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Los grupos commodity compensan el coste de las operaciones high-touch con ataques masivos que convierten a **los motores de búsqueda & redes de anuncios en el canal de entrega**.

1. **SEO poisoning / malvertising** impulsa un resultado falso como `chromium-update[.]site` a los primeros anuncios de búsqueda.
2. La víctima descarga un pequeño **first-stage loader** (a menudo JS/HTA/ISO). Ejemplos observados por Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. El loader exfiltra cookies del navegador + bases de datos de credenciales, luego descarga un **silent loader** que decide – *en tiempo real* – si desplegar:
* RAT (p. ej. AsyncRAT, RustDesk)
* ransomware / wiper
* componente de persistencia (clave Run en registry + tarea programada)

### Consejos de hardening
* Bloquear dominios recién registrados y aplicar **Advanced DNS / URL Filtering** en *search-ads* además del email.
* Restringir la instalación de software a paquetes MSI firmados / Store, denegar la ejecución de `HTA`, `ISO`, `VBS` por política.
* Monitorizar procesos hijo de navegadores que abran instaladores:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Buscar LOLBins frecuentemente abusados por loaders de primera etapa (p. ej. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Los atacantes ahora encadenan **APIs LLM & de clonación de voz** para cebos totalmente personalizados e interacción en tiempo real.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Añadir **banners dinámicos** que destaquen mensajes enviados desde automatización no confiable (mediante anomalías ARC/DKIM).  
• Desplegar **frases de desafío biométricas de voz** para solicitudes telefónicas de alto riesgo.  
• Simular continuamente cebos generados por IA en los programas de concienciación – las plantillas estáticas están obsoletas.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Además del push-bombing clásico, los operadores simplemente **forzan un nuevo registro MFA** durante la llamada al help-desk, anulando el token existente del usuario. Cualquier solicitud de inicio de sesión posterior parecerá legítima para la víctima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitorear eventos de AzureAD/AWS/Okta donde **`deleteMFA` + `addMFA`** ocurran **en cuestión de minutos desde la misma IP**.



## Clipboard Hijacking / Pastejacking

Los atacantes pueden copiar silenciosamente comandos maliciosos en el clipboard de la víctima desde una página web comprometida o typosquatted y luego engañar al usuario para que los pegue en **Win + R**, **Win + X** o una ventana de terminal, ejecutando código arbitrario sin ninguna descarga o adjunto.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## Referencias

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
