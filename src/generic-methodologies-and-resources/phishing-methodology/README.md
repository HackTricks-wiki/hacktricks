# Metodología de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodología

1. Recon a la víctima
1. Select the **victim domain**.
2. Realiza una enumeración web básica **buscando portales de acceso** usados por la víctima y **decide** cuál vas a **suplantar**.
3. Usa algo de **OSINT** para **encontrar correos electrónicos**.
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

- **Keyword**: El nombre de dominio **contiene** una **keyword** importante del dominio original (e.g., zelster.com-management.com).
- **hypened subdomain**: Cambia el **punto por un guion** de un subdominio (e.g., www-zelster.com).
- **New TLD**: Mismo dominio usando un **nuevo TLD** (e.g., zelster.org)
- **Homoglyph**: Sustituye una letra en el nombre de dominio por **letras que se parecen** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Intercambia dos letras dentro del nombre de dominio (e.g., zelsetr.com).
- **Singularization/Pluralization**: Agrega o elimina una “s” al final del nombre de dominio (e.g., zeltsers.com).
- **Omission**: Elimina una de las letras del nombre de dominio (e.g., zelser.com).
- **Repetition:** Repite una de las letras en el nombre de dominio (e.g., zeltsser.com).
- **Replacement**: Como homoglyph pero menos sigiloso. Sustituye una de las letras en el nombre de dominio, quizá por una letra cercana a la original en el teclado (e.g, zektser.com).
- **Subdomained**: Introduce un **punto** dentro del nombre de dominio (e.g., ze.lster.com).
- **Insertion**: Inserta una letra en el nombre de dominio (e.g., zerltser.com).
- **Missing dot**: Añade la TLD al nombre de dominio sin el punto. (e.g., zelstercom.com)

**Herramientas automáticas**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sitios web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Existe la **posibilidad de que uno o varios bits almacenados o en comunicación se inviertan automáticamente** debido a varios factores como las erupciones solares, los rayos cósmicos o errores de hardware.

Cuando este concepto se **aplica a las solicitudes DNS**, es posible que el **dominio recibido por el servidor DNS** no sea el mismo que el solicitado inicialmente.

Por ejemplo, una modificación de un solo bit en el dominio "windows.com" puede cambiarlo a "windnws.com".

Los atacantes pueden **aprovechar esto registrando múltiples dominios con bit-flipping** que sean similares al dominio de la víctima. Su intención es redirigir a usuarios legítimos a su propia infraestructura.

Para más información lee [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Comprar un dominio confiable

Puedes buscar en [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio expirado que puedas usar.\
Para asegurarte de que el dominio expirado que vas a comprar **ya tiene un buen SEO** puedes comprobar cómo está categorizado en:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Descubrimiento de correos electrónicos

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Para **descubrir más** direcciones de email válidas o **verificar las que** ya has descubierto, puedes comprobar si puedes hacer brute-force contra los servidores SMTP de la víctima. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Además, no olvides que si los usuarios usan **algún portal web para acceder a sus correos**, puedes comprobar si es vulnerable a **username brute force**, y explotar la vulnerabilidad si es posible.

## Configuración de GoPhish

### Instalación

Puedes descargarlo desde [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Descarga y descomprímelo dentro de `/opt/gophish` y ejecuta `/opt/gophish/gophish`\
Se te mostrará una contraseña para el usuario admin en el puerto 3333 en la salida. Por tanto, accede a ese puerto y usa esas credenciales para cambiar la contraseña de admin. Puede que necesites tunelizar ese puerto a local:
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

Instala: `apt-get install postfix`

Luego añade el dominio a los siguientes archivos:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

Cambia también los valores de las siguientes variables dentro de /etc/postfix/main.cf

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Finalmente modifica los archivos **`/etc/hostname`** y **`/etc/mailname`** con tu nombre de dominio y **reinicia tu VPS.**

Ahora crea un **registro DNS A** de `mail.<domain>` apuntando a la **dirección IP** del VPS y un **registro DNS MX** apuntando a `mail.<domain>`

Ahora probemos enviar un correo:
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

Para crear el servicio gophish para que pueda iniciarse automáticamente y gestionarse como servicio, puedes crear el archivo `/etc/init.d/gophish` con el siguiente contenido:
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
Termina de configurar el servicio y comprueba que esté funcionando:
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
## Configuring mail server and domain

### Wait & be legit

Cuanto más antiguo sea un dominio, menos probable es que sea marcado como spam. Por eso debes esperar el mayor tiempo posible (al menos 1 semana) antes de la evaluación de phishing. Además, si publicas una página relacionada con un sector con buena reputación, la reputación obtenida será mejor.

Ten en cuenta que, aunque tengas que esperar una semana, puedes terminar de configurar todo ahora.

### Configure Reverse DNS (rDNS) record

Configura un registro rDNS (PTR) que resuelva la dirección IP del VPS al nombre de dominio.

### Sender Policy Framework (SPF) Record

Debes **configurar un registro SPF para el nuevo dominio**. Si no sabes qué es un registro SPF [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

You can use [https://www.spfwizard.net/](https://www.spfwizard.net) to generate your SPF policy (use the IP of the VPS machine)

![](<../../images/image (1037).png>)

This is the content that must be set inside a TXT record inside the domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro DMARC (Domain-based Message Authentication, Reporting & Conformance)

Debes **configurar un registro DMARC para el nuevo dominio**. Si no sabes qué es un registro DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Debes crear un nuevo registro DNS TXT que apunte al hostname `_dmarc.<domain>` con el siguiente contenido:
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

### Prueba la puntuación de la configuración de tu email

Puedes hacerlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Simplemente accede a la página y envía un email a la dirección que te dan:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
También puedes **comprobar la configuración de tu email** enviando un email a `check-auth@verifier.port25.com` y **leer la respuesta** (para esto necesitarás **abrir** port **25** y ver la respuesta en el archivo _/var/mail/root_ si envías el email como root).\
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
También podrías enviar **un mensaje a una cuenta de Gmail bajo tu control**, y revisar los **encabezados del correo** en tu bandeja de entrada de Gmail, `dkim=pass` debería estar presente en el campo `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Eliminación de Spamhouse Blacklist

La página [www.mail-tester.com](https://www.mail-tester.com) puede indicarte si tu dominio está siendo bloqueado por spamhouse. Puedes solicitar que tu dominio/IP sea eliminado en: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Eliminación de Microsoft Blacklist

​​Puedes solicitar que tu dominio/IP sea eliminado en [https://sender.office.com/](https://sender.office.com).

## Crear y lanzar campaña de GoPhish

### Perfil de envío

- Pon algún **nombre para identificar** el perfil del remitente
- Decide desde qué cuenta vas a enviar los correos de phishing. Sugerencias: _noreply, support, servicedesk, salesforce..._
- Puedes dejar en blanco el username y password, pero asegúrate de marcar la opción Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Se recomienda usar la funcionalidad "**Send Test Email**" para comprobar que todo funciona.\
> Recomendaría **enviar los correos de prueba a direcciones 10min mails** para evitar ser blacklisted al hacer pruebas.

### Plantilla de email

- Pon algún **nombre para identificar** la plantilla
- Luego escribe un **subject** (nada extraño, algo que podrías esperar leer en un correo normal)
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
Tenga en cuenta que, para **aumentar la credibilidad del correo**, se recomienda usar alguna firma de un correo real del cliente. Sugerencias:

- Enviar un correo a una **dirección inexistente** y comprobar si la respuesta contiene alguna firma.
- Buscar **correos públicos** como info@ex.com o press@ex.com o public@ex.com y enviarles un correo y esperar la respuesta.
- Intentar contactar **algún email válido descubierto** y esperar la respuesta.

![](<../../images/image (80).png>)

> [!TIP]
> La Plantilla de Email también permite **adjuntar archivos para enviar**. Si además quieres robar desafíos NTLM usando algunos ficheros/documentos especialmente diseñados [lee esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Página de aterrizaje

- Escribir un **nombre**
- **Escribir el código HTML** de la página web. Ten en cuenta que puedes **importar** páginas web.
- Marcar **Capture Submitted Data** y **Capture Passwords**
- Configurar una **redirección**

![](<../../images/image (826).png>)

> [!TIP]
> Normalmente necesitarás modificar el código HTML de la página y hacer algunas pruebas localmente (quizá usando algún servidor Apache) **hasta que te gusten los resultados.** Luego, escribe ese código HTML en el recuadro.\
> Ten en cuenta que si necesitas **usar algunos recursos estáticos** para el HTML (quizá CSS y JS) puedes guardarlos en _**/opt/gophish/static/endpoint**_ y luego acceder a ellos desde _**/static/\<filename>**_

> [!TIP]
> Para la redirección podrías **redirigir a los usuarios a la página legítima principal** de la víctima, o redirigirlos a _/static/migration.html_ por ejemplo, poner una **rueda de carga (**[**https://loading.io/**](https://loading.io)**)  durante 5 segundos y luego indicar que el proceso fue exitoso**.

### Usuarios y Grupos

- Poner un nombre
- **Importar los datos** (nota que para usar la plantilla de ejemplo necesitas el firstname, last name y email address de cada usuario)

![](<../../images/image (163).png>)

### Campaña

Finalmente, crea una campaña seleccionando un nombre, la plantilla de email, la landing page, la URL, el perfil de envío y el grupo. Ten en cuenta que la URL será el enlace enviado a las víctimas.

Ten en cuenta que el **Sending Profile permite enviar un email de prueba para ver cómo quedará el phishing final**:

![](<../../images/image (192).png>)

> [!TIP]
> Recomendaría **enviar los correos de prueba a direcciones 10min mails** para evitar ser incluido en listas negras mientras realizas pruebas.

¡Una vez que todo esté listo, lanza la campaña!

## Clonación de sitio web

Si por alguna razón quieres clonar el sitio web consulta la siguiente página:


{{#ref}}
clone-a-website.md
{{#endref}}

## Documentos y archivos con backdoor

En algunas evaluaciones de phishing (principalmente para Red Teams) querrás también **enviar archivos que contengan algún tipo de backdoor** (quizá un C2 o quizá algo que provoque una autenticación).\
Consulta la siguiente página para algunos ejemplos:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Vía Proxy MitM

El ataque anterior es bastante ingenioso ya que estás falsificando una web real y recopilando la información introducida por el usuario. Desafortunadamente, si el usuario no introduce la contraseña correcta o si la aplicación que has falsificado está configurada con 2FA, **esta información no te permitirá suplantar al usuario engañado**.

Aquí es donde herramientas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) y [**muraena**](https://github.com/muraenateam/muraena) resultan útiles. Esta herramienta te permitirá generar un ataque MitM. Básicamente, el ataque funciona de la siguiente manera:

1. Tú **suplantas el formulario de login** de la página real.
2. El usuario **envía** sus **credenciales** a tu página falsa y la herramienta las reenvía a la página real, **comprobando si funcionan**.
3. Si la cuenta está configurada con **2FA**, la página MitM pedirá ese código y, una vez que el **usuario lo introduce**, la herramienta lo enviará a la página real.
4. Una vez el usuario está autenticado, tú (como atacante) habrás **capturado las credenciales, el 2FA, la cookie y cualquier información** de cada interacción mientras la herramienta realiza el MitM.

### Vía VNC

¿Qué pasa si, en lugar de **enviar a la víctima a una página maliciosa** con la misma apariencia que la original, la envías a una **sesión VNC con un navegador conectado a la página real**? Podrás ver lo que hace, robar la contraseña, la MFA utilizada, las cookies...\
Puedes hacer esto con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detectando la detección

Obviamente una de las mejores formas de saber si te han descubierto es **buscar tu dominio en listas negras**. Si aparece listado, de alguna forma tu dominio fue detectado como sospechoso.\
Una forma fácil de comprobar si tu dominio aparece en alguna blacklist es usar [https://malwareworld.com/](https://malwareworld.com)

Sin embargo, hay otras formas de saber si la víctima está **buscando activamente actividad de phishing sospechosa en el entorno** como se explica en:


{{#ref}}
detecting-phising.md
{{#endref}}

Puedes **comprar un dominio con un nombre muy similar** al dominio de la víctima **y/o generar un certificado** para un **subdominio** de un dominio controlado por ti **conteniendo** la **palabra clave** del dominio de la víctima. Si la **víctima** realiza cualquier tipo de interacción DNS o HTTP con ellos, sabrás que **está buscando activamente** dominios sospechosos y tendrás que ser muy sigiloso.

### Evaluar el phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious) para evaluar si tu email va a terminar en la carpeta de spam o si va a ser bloqueado o tendrá éxito.

## Compromiso de identidad de alto contacto (Reseteo de MFA vía Help-Desk)

Los conjuntos de intrusión modernos cada vez más omiten por completo los correos y **apuntan directamente al flujo de trabajo del service-desk / recuperación de identidad** para derrotar el MFA. El ataque es completamente "living-off-the-land": una vez que el operador posee credenciales válidas pivotan con herramientas administrativas integradas – no se requiere malware.

### Flujo del ataque
1. Recon de la víctima
* Recolectar detalles personales y corporativos de LinkedIn, breaches de datos, GitHub público, etc.
* Identificar identidades de alto valor (ejecutivos, IT, finanzas) y enumerar el **proceso exacto del help-desk** para reset de contraseña / MFA.
2. Ingeniería social en tiempo real
* Llamar por teléfono, Teams o chat al help-desk haciéndose pasar por el objetivo (a menudo con **caller-ID spoofing** o **voz clonada**).
* Proporcionar la PII previamente recolectada para pasar la verificación basada en conocimiento.
* Convencer al agente para que **resetee el secreto MFA** o realice un **SIM-swap** en un número móvil registrado.
3. Acciones inmediatas post-acceso (≤60 min en casos reales)
* Establecer un foothold a través de cualquier portal web SSO.
* Enumerar AD / AzureAD con herramientas integradas (sin dropear binarios):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Movimiento lateral con **WMI**, **PsExec**, o agentes legítimos **RMM** ya en la whitelist del entorno.

### Detección y mitigación
* Tratar la recuperación de identidad por help-desk como una **operación privilegiada** – requerir step-up auth y aprobación de manager.
* Desplegar **Identity Threat Detection & Response (ITDR)** / reglas **UEBA** que alerten sobre:
* Método MFA cambiado + autenticación desde un nuevo dispositivo / geo.
* Elevación inmediata del mismo principal (user → admin).
* Grabar llamadas del help-desk y aplicar un **call-back a un número ya registrado** antes de cualquier reset.
* Implementar **Just-In-Time (JIT) / Privileged Access** para que las cuentas recién reseteadas **no** hereden automáticamente tokens de alto privilegio.

---

## Decepción a gran escala – SEO Poisoning y campañas “ClickFix”
Las crews commodity compensan el coste de las operaciones de alto contacto con ataques masivos que convierten a los **motores de búsqueda y redes de anuncios en el canal de entrega**.

1. **SEO poisoning / malvertising** impulsa un resultado falso como `chromium-update[.]site` a los anuncios de búsqueda principales.
2. La víctima descarga un pequeño **first-stage loader** (a menudo JS/HTA/ISO). Ejemplos vistos por Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. El loader exfiltra cookies del navegador + DBs de credenciales, luego descarga un **silent loader** que decide – *en tiempo real* – si desplegar:
* RAT (p. ej. AsyncRAT, RustDesk)
* ransomware / wiper
* componente de persistencia (clave Run del registro + tarea programada)

### Consejos de hardening
* Bloquear dominios recién registrados y aplicar **Advanced DNS / URL Filtering** en *search-ads* así como en e-mail.
* Restringir la instalación de software a paquetes MSI firmados / Store, denegar la ejecución de `HTA`, `ISO`, `VBS` por política.
* Monitorizar procesos hijos de navegadores que abran instaladores:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Buscar LOLBins frecuentemente abusados por loaders de primera etapa (p. ej. `regsvr32`, `curl`, `mshta`).

---

## Operaciones de phishing mejoradas con IA
Los atacantes ahora encadenan **APIs LLM y de clonación de voz** para cebos totalmente personalizados e interacción en tiempo real.

| Capa | Ejemplo de uso por el actor de amenaza |
|------|----------------------------------------|
| Automatización | Generar y enviar >100 k emails / SMS con redacción aleatoria y enlaces de tracking. |
| IA generativa | Producir correos *one-off* que hagan referencia a M&A públicas, chistes internos de redes sociales; voz deep-fake del CEO en una llamada de suplantación. |
| IA agentiva | Registrar dominios de forma autónoma, raspar intel open-source, crear emails de siguiente etapa cuando una víctima hace clic pero no envía credenciales. |

**Defensa:**
• Añadir **banners dinámicos** que destaquen mensajes enviados desde automatizaciones no confiables (por anomalías ARC/DKIM).  
• Desplegar **frases de desafío biométrico de voz** para solicitudes telefónicas de alto riesgo.  
• Simular continuamente cebos generados por IA en los programas de concienciación – las plantillas estáticas están obsoletas.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Variante Push Bombing – Forced Reset
Además del push-bombing clásico, los operadores simplemente **forzan un nuevo registro MFA** durante la llamada al help-desk, aniquilando el token existente del usuario. Cualquier solicitud de inicio de sesión subsecuente parecerá legítima para la víctima.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitorea eventos de AzureAD/AWS/Okta donde **`deleteMFA` + `addMFA`** ocurran **en minutos desde la misma IP**.



## Clipboard Hijacking / Pastejacking

Los atacantes pueden copiar silenciosamente comandos maliciosos en el portapapeles de la víctima desde una página web comprometida o typosquatted y luego engañar al usuario para que los pegue dentro de **Win + R**, **Win + X** o una ventana de terminal, ejecutando código arbitrario sin ninguna descarga o archivo adjunto.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Los operadores cada vez más colocan sus flujos de phishing detrás de una comprobación simple del dispositivo para que los crawlers de escritorio nunca lleguen a las páginas finales. Un patrón común es un pequeño script que prueba si el DOM es compatible con touch y envía el resultado a un endpoint del servidor; los clientes no móviles reciben HTTP 500 (o una página en blanco), mientras que a los usuarios móviles se les sirve el flujo completo.

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
- Establece una cookie de sesión durante la primera carga.
- Acepta `POST /detect {"is_mobile":true|false}`.
- Devuelve 500 (o placeholder) en GETs posteriores cuando `is_mobile=false`; sirve phishing solo si `true`.

Heurísticas de hunting y detección:
- Consulta urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetría web: secuencia de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 para no‑móviles; rutas legítimas de víctimas móviles devuelven 200 con HTML/JS posterior.
- Bloquear o escrutar páginas que condicionen el contenido exclusivamente a `ontouchstart` u otras comprobaciones de dispositivo similares.

Consejos de defensa:
- Ejecutar crawlers con fingerprints de tipo móvil y JS habilitado para revelar contenido restringido.
- Generar alertas por respuestas 500 sospechosas tras `POST /detect` en dominios recién registrados.

## Referencias

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
