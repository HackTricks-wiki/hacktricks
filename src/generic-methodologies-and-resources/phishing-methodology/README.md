# Metodología de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodología

1. Reconocer a la víctima
1. Seleccionar el **dominio de la víctima**.
2. Realizar una enumeración web básica **buscando portales de inicio de sesión** utilizados por la víctima y **decidir** cuál vas a **suplantar**.
3. Usar **OSINT** para **encontrar correos electrónicos**.
2. Preparar el entorno
1. **Comprar el dominio** que vas a usar para la evaluación de phishing.
2. **Configurar el servicio de correo** relacionado (SPF, DMARC, DKIM, rDNS).
3. Configurar el VPS con **gophish**.
3. Preparar la campaña
1. Preparar la **plantilla de correo electrónico**.
2. Preparar la **página web** para robar las credenciales.
4. ¡Lanzar la campaña!

## Generar nombres de dominio similares o comprar un dominio de confianza

### Técnicas de Variación de Nombres de Dominio

- **Palabra clave**: El nombre de dominio **contiene** una **palabra clave** importante del dominio original (por ejemplo, zelster.com-management.com).
- **subdominio con guion**: Cambiar el **punto por un guion** de un subdominio (por ejemplo, www-zelster.com).
- **Nuevo TLD**: Mismo dominio usando un **nuevo TLD** (por ejemplo, zelster.org).
- **Homoglyph**: **Reemplaza** una letra en el nombre de dominio con **letras que se ven similares** (por ejemplo, zelfser.com).
- **Transposición:** **Intercambia dos letras** dentro del nombre de dominio (por ejemplo, zelsetr.com).
- **Singularización/Pluralización**: Agrega o quita “s” al final del nombre de dominio (por ejemplo, zeltsers.com).
- **Omisión**: **Elimina una** de las letras del nombre de dominio (por ejemplo, zelser.com).
- **Repetición:** **Repite una** de las letras en el nombre de dominio (por ejemplo, zeltsser.com).
- **Reemplazo**: Como homoglyph pero menos sigiloso. Reemplaza una de las letras en el nombre de dominio, quizás con una letra cercana a la letra original en el teclado (por ejemplo, zektser.com).
- **Subdominado**: Introducir un **punto** dentro del nombre de dominio (por ejemplo, ze.lster.com).
- **Inserción**: **Inserta una letra** en el nombre de dominio (por ejemplo, zerltser.com).
- **Punto faltante**: Agregar el TLD al nombre de dominio. (por ejemplo, zelstercom.com)

**Herramientas Automáticas**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sitios Web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Hay una **posibilidad de que uno de algunos bits almacenados o en comunicación pueda ser automáticamente invertido** debido a varios factores como llamaradas solares, rayos cósmicos o errores de hardware.

Cuando este concepto se **aplica a las solicitudes DNS**, es posible que el **dominio recibido por el servidor DNS** no sea el mismo que el dominio solicitado inicialmente.

Por ejemplo, una modificación de un solo bit en el dominio "windows.com" puede cambiarlo a "windnws.com".

Los atacantes pueden **aprovechar esto registrando múltiples dominios de bit-flipping** que son similares al dominio de la víctima. Su intención es redirigir a los usuarios legítimos a su propia infraestructura.

Para más información, lee [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Comprar un dominio de confianza

Puedes buscar en [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio expirado que podrías usar.\
Para asegurarte de que el dominio expirado que vas a comprar **ya tiene un buen SEO**, podrías buscar cómo está categorizado en:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Descubriendo Correos Electrónicos

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratis)
- [https://phonebook.cz/](https://phonebook.cz) (100% gratis)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Para **descubrir más** direcciones de correo electrónico válidas o **verificar las que ya has descubierto**, puedes comprobar si puedes forzar por fuerza bruta los servidores smtp de la víctima. [Aprende cómo verificar/descubrir direcciones de correo electrónico aquí](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Además, no olvides que si los usuarios utilizan **cualquier portal web para acceder a sus correos**, puedes verificar si es vulnerable a **fuerza bruta de nombres de usuario** y explotar la vulnerabilidad si es posible.

## Configurando GoPhish

### Instalación

Puedes descargarlo de [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Descarga y descomprime en `/opt/gophish` y ejecuta `/opt/gophish/gophish`\
Se te dará una contraseña para el usuario administrador en el puerto 3333 en la salida. Por lo tanto, accede a ese puerto y usa esas credenciales para cambiar la contraseña del administrador. Puede que necesites tunelizar ese puerto a local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuración

**Configuración del certificado TLS**

Antes de este paso, deberías haber **comprado ya el dominio** que vas a usar y debe estar **apuntando** a la **IP del VPS** donde estás configurando **gophish**.
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

Luego agrega el dominio a los siguientes archivos:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Cambia también los valores de las siguientes variables dentro de /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Finalmente, modifica los archivos **`/etc/hostname`** y **`/etc/mailname`** a tu nombre de dominio y **reinicia tu VPS.**

Ahora, crea un **registro A de DNS** de `mail.<domain>` apuntando a la **dirección IP** del VPS y un **registro MX de DNS** apuntando a `mail.<domain>`

Ahora probemos enviar un correo:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuración de Gophish**

Detén la ejecución de gophish y configuremoslo.\
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

Para crear el servicio gophish para que se inicie automáticamente y se gestione como un servicio, puedes crear el archivo `/etc/init.d/gophish` con el siguiente contenido:
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
Termina de configurar el servicio y verifica su funcionamiento haciendo:
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

### Espera y sé legítimo

Cuanto más antiguo sea un dominio, menos probable es que sea detectado como spam. Por lo tanto, debes esperar el mayor tiempo posible (al menos 1 semana) antes de la evaluación de phishing. Además, si pones una página sobre un sector reputacional, la reputación obtenida será mejor.

Ten en cuenta que incluso si tienes que esperar una semana, puedes terminar de configurar todo ahora.

### Configurar el registro de DNS inverso (rDNS)

Configura un registro rDNS (PTR) que resuelva la dirección IP del VPS al nombre de dominio.

### Registro de Marco de Políticas de Remitente (SPF)

Debes **configurar un registro SPF para el nuevo dominio**. Si no sabes qué es un registro SPF [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puedes usar [https://www.spfwizard.net/](https://www.spfwizard.net) para generar tu política SPF (usa la IP de la máquina VPS)

![](<../../images/image (1037).png>)

Este es el contenido que debe establecerse dentro de un registro TXT dentro del dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro de Autenticación de Mensajes Basado en Dominio, Informes y Conformidad (DMARC)

Debes **configurar un registro DMARC para el nuevo dominio**. Si no sabes qué es un registro DMARC [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Tienes que crear un nuevo registro DNS TXT apuntando al nombre de host `_dmarc.<domain>` con el siguiente contenido:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Debes **configurar un DKIM para el nuevo dominio**. Si no sabes qué es un registro DMARC [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Este tutorial se basa en: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!NOTE]
> Necesitas concatenar ambos valores B64 que genera la clave DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Prueba tu puntuación de configuración de correo electrónico

Puedes hacerlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Solo accede a la página y envía un correo electrónico a la dirección que te den:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
También puedes **verificar la configuración de tu correo electrónico** enviando un correo a `check-auth@verifier.port25.com` y **leyendo la respuesta** (para esto necesitarás **abrir** el puerto **25** y ver la respuesta en el archivo _/var/mail/root_ si envías el correo como root).\
Verifica que pases todas las pruebas:
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
También podrías enviar un **mensaje a un Gmail bajo tu control** y verificar los **encabezados del correo electrónico** en tu bandeja de entrada de Gmail, `dkim=pass` debería estar presente en el campo de encabezado `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Eliminación de la lista negra de Spamhouse

La página [www.mail-tester.com](https://www.mail-tester.com) puede indicarte si tu dominio está siendo bloqueado por spamhouse. Puedes solicitar la eliminación de tu dominio/IP en: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Eliminación de la lista negra de Microsoft

​​Puedes solicitar la eliminación de tu dominio/IP en [https://sender.office.com/](https://sender.office.com).

## Crear y lanzar campaña de GoPhish

### Perfil de envío

- Establece un **nombre para identificar** el perfil del remitente
- Decide desde qué cuenta vas a enviar los correos electrónicos de phishing. Sugerencias: _noreply, support, servicedesk, salesforce..._
- Puedes dejar en blanco el nombre de usuario y la contraseña, pero asegúrate de marcar la opción Ignorar Errores de Certificado

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!NOTE]
> Se recomienda utilizar la funcionalidad "**Enviar correo de prueba**" para verificar que todo esté funcionando.\
> Recomendaría **enviar los correos de prueba a direcciones de 10min** para evitar ser incluido en la lista negra durante las pruebas.

### Plantilla de correo electrónico

- Establece un **nombre para identificar** la plantilla
- Luego escribe un **asunto** (nada extraño, solo algo que podrías esperar leer en un correo electrónico regular)
- Asegúrate de haber marcado "**Agregar imagen de seguimiento**"
- Escribe la **plantilla de correo electrónico** (puedes usar variables como en el siguiente ejemplo):
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
Nota que **para aumentar la credibilidad del correo electrónico**, se recomienda usar alguna firma de un correo del cliente. Sugerencias:

- Envía un correo a una **dirección inexistente** y verifica si la respuesta tiene alguna firma.
- Busca **correos públicos** como info@ex.com o press@ex.com o public@ex.com y envíales un correo y espera la respuesta.
- Intenta contactar **algún correo válido descubierto** y espera la respuesta.

![](<../../images/image (80).png>)

> [!NOTE]
> La plantilla de correo también permite **adjuntar archivos para enviar**. Si también deseas robar desafíos NTLM usando algunos archivos/documentos especialmente diseñados [lee esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Página de Aterrizaje

- Escribe un **nombre**
- **Escribe el código HTML** de la página web. Nota que puedes **importar** páginas web.
- Marca **Capturar Datos Enviados** y **Capturar Contraseñas**
- Establece una **redirección**

![](<../../images/image (826).png>)

> [!NOTE]
> Generalmente necesitarás modificar el código HTML de la página y hacer algunas pruebas en local (quizás usando algún servidor Apache) **hasta que te gusten los resultados.** Luego, escribe ese código HTML en el cuadro.\
> Nota que si necesitas **usar algunos recursos estáticos** para el HTML (quizás algunas páginas CSS y JS) puedes guardarlos en _**/opt/gophish/static/endpoint**_ y luego acceder a ellos desde _**/static/\<filename>**_

> [!NOTE]
> Para la redirección podrías **redirigir a los usuarios a la página web principal legítima** de la víctima, o redirigirlos a _/static/migration.html_ por ejemplo, poner alguna **rueda giratoria (**[**https://loading.io/**](https://loading.io)**) durante 5 segundos y luego indicar que el proceso fue exitoso**.

### Usuarios y Grupos

- Establece un nombre
- **Importa los datos** (nota que para usar la plantilla del ejemplo necesitas el nombre, apellido y dirección de correo electrónico de cada usuario)

![](<../../images/image (163).png>)

### Campaña

Finalmente, crea una campaña seleccionando un nombre, la plantilla de correo, la página de aterrizaje, la URL, el perfil de envío y el grupo. Nota que la URL será el enlace enviado a las víctimas.

Nota que el **Perfil de Envío permite enviar un correo de prueba para ver cómo se verá el correo de phishing final**:

![](<../../images/image (192).png>)

> [!NOTE]
> Recomendaría **enviar los correos de prueba a direcciones de 10min** para evitar ser bloqueado al hacer pruebas.

Una vez que todo esté listo, ¡simplemente lanza la campaña!

## Clonación de Sitios Web

Si por alguna razón deseas clonar el sitio web, consulta la siguiente página:

{{#ref}}
clone-a-website.md
{{#endref}}

## Documentos y Archivos con Puerta Trasera

En algunas evaluaciones de phishing (principalmente para Red Teams) también querrás **enviar archivos que contengan algún tipo de puerta trasera** (quizás un C2 o tal vez solo algo que active una autenticación).\
Consulta la siguiente página para algunos ejemplos:

{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### A través de Proxy MitM

El ataque anterior es bastante ingenioso ya que estás falsificando un sitio web real y recopilando la información proporcionada por el usuario. Desafortunadamente, si el usuario no ingresó la contraseña correcta o si la aplicación que falsificaste está configurada con 2FA, **esta información no te permitirá suplantar al usuario engañado**.

Aquí es donde herramientas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) y [**muraena**](https://github.com/muraenateam/muraena) son útiles. Esta herramienta te permitirá generar un ataque tipo MitM. Básicamente, los ataques funcionan de la siguiente manera:

1. **Suplantas el formulario de inicio de sesión** de la página web real.
2. El usuario **envía** sus **credenciales** a tu página falsa y la herramienta envía esas credenciales a la página web real, **verificando si las credenciales funcionan**.
3. Si la cuenta está configurada con **2FA**, la página MitM lo pedirá y una vez que el **usuario lo introduzca**, la herramienta lo enviará a la página web real.
4. Una vez que el usuario esté autenticado, tú (como atacante) habrás **capturado las credenciales, el 2FA, la cookie y cualquier información** de cada interacción mientras la herramienta realiza un MitM.

### A través de VNC

¿Qué pasaría si en lugar de **enviar a la víctima a una página maliciosa** con el mismo aspecto que la original, lo envías a una **sesión VNC con un navegador conectado a la página web real**? Podrás ver lo que hace, robar la contraseña, el MFA utilizado, las cookies...\
Puedes hacer esto con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detectando la detección

Obviamente, una de las mejores maneras de saber si te han descubierto es **buscar tu dominio en listas negras**. Si aparece listado, de alguna manera tu dominio fue detectado como sospechoso.\
Una forma fácil de verificar si tu dominio aparece en alguna lista negra es usar [https://malwareworld.com/](https://malwareworld.com)

Sin embargo, hay otras formas de saber si la víctima está **buscando activamente actividad de phishing sospechosa en la naturaleza** como se explica en:

{{#ref}}
detecting-phising.md
{{#endref}}

Puedes **comprar un dominio con un nombre muy similar** al dominio de la víctima **y/o generar un certificado** para un **subdominio** de un dominio controlado por ti **que contenga** la **palabra clave** del dominio de la víctima. Si la **víctima** realiza algún tipo de **interacción DNS o HTTP** con ellos, sabrás que **está buscando activamente** dominios sospechosos y necesitarás ser muy sigiloso.

### Evaluar el phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious) para evaluar si tu correo va a terminar en la carpeta de spam o si va a ser bloqueado o exitoso.

## Referencias

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{{#include ../../banners/hacktricks-training.md}}
