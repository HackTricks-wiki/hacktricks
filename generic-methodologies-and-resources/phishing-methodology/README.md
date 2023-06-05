# Metodología de Phishing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Metodología

1. Reconocimiento de la víctima
   1. Selecciona el **dominio de la víctima**.
   2. Realiza una enumeración web básica **buscando portales de inicio de sesión** utilizados por la víctima y **decide** cuál vas a **suplantar**.
   3. Usa algunas **herramientas de OSINT** para **encontrar correos electrónicos**.
2. Prepara el entorno
   1. **Compra el dominio** que vas a utilizar para la evaluación de phishing.
   2. **Configura el servicio de correo electrónico** relacionado con los registros (SPF, DMARC, DKIM, rDNS)
   3. Configura el VPS con **gophish**
3. Prepara la campaña
   1. Prepara la **plantilla de correo electrónico**
   2. Prepara la **página web** para robar las credenciales
4. ¡Lanza la campaña!

## Generar nombres de dominio similares o comprar un dominio de confianza

### Técnicas de variación de nombres de dominio

* **Palabra clave**: El nombre de dominio **contiene** una **palabra clave** importante del dominio original (por ejemplo, zelster.com-management.com).
* **Subdominio con guión**: Cambia el **punto por un guión** de un subdominio (por ejemplo, www-zelster.com).
* **Nuevo TLD**: Mismo dominio utilizando un **nuevo TLD** (por ejemplo, zelster.org)
* **Homógrafo**: Se **reemplaza** una letra en el nombre de dominio con **letras que se parecen** (por ejemplo, zelfser.com).
* **Transposición:** Se **intercambian dos letras** dentro del nombre de dominio (por ejemplo, zelster.com).
* **Singularización/Pluralización**: Agrega o elimina "s" al final del nombre de dominio (por ejemplo, zeltsers.com).
* **Omisión**: Se **elimina una** de las letras del nombre de dominio (por ejemplo, zelser.com).
* **Repetición**: Se **repite una** de las letras del nombre de dominio (por ejemplo, zeltsser.com).
* **Reemplazo**: Como homógrafo pero menos sigiloso. Se reemplaza una de las letras del nombre de dominio, tal vez con una letra en proximidad de la letra original en el teclado (por ejemplo, zektser.com).
* **Subdominado**: Introduce un **punto** dentro del nombre de dominio (por ejemplo, ze.lster.com).
* **Inserción**: Se **inserta una letra** en el nombre de dominio (por ejemplo, zerltser.com).
* **Punto faltante**: Agrega el TLD al nombre de dominio. (por ejemplo, zelstercom.com)

**Herramientas automáticas**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sitios web**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

En el mundo de la informática, todo se almacena en bits (ceros y unos) en la memoria detrás de escena.\
Esto también se aplica a los dominios. Por ejemplo, _windows.com_ se convierte en _01110111..._ en la memoria volátil de su dispositivo informático.\
Sin embargo, ¿qué sucede si uno de estos bits se invierte automáticamente debido a una llamarada solar, rayos cósmicos o un error de hardware? Es decir, uno de los 0 se convierte en 1 y viceversa.\
Aplicando este concepto a la solicitud DNS, es posible que el **dominio solicitado** que llega al servidor DNS **no sea el mismo que el dominio solicitado inicialmente**.

Por ejemplo, una modificación de 1 bit en el dominio windows.com puede transformarlo en _windnws.com._\
**Los atacantes pueden registrar tantos dominios de bit-flipping como sea posible relacionados con la víctima para redirigir a los usuarios legítimos a su infraestructura**.

Para obtener más información, lea [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Compra un dominio de confianza

Puedes buscar en [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio caducado que puedas utilizar.\
Para asegurarte de que el dominio caducado que vas a comprar **ya tiene un buen SEO**, puedes buscar cómo se categoriza en:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Descubriendo correos electrónicos

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratis)
* [https://phonebook.cz/](https://phonebook.cz) (100% gratis)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Para **descubrir más** direcciones de correo electrónico válidas o **verificar las que** ya has descubierto, puedes comprobar si puedes hacer fuerza bruta en los servidores SMTP de la víctima. [Aprende cómo verificar/descubrir direcciones de correo electrónico aquí](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Además, no olvides que si los usuarios usan **cualquier portal web para acceder a sus correos electrónicos**, puedes comprobar si es vulnerable a la **fuerza bruta de nombres de usuario**, y explotar la vulnerabilidad si es posible.

## Configurando GoPhish

### Instalación

Puedes descargarlo desde [https://
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuración

**Configuración del certificado TLS**

Antes de este paso, **deberías haber comprado el dominio** que vas a utilizar y debe estar **apuntando** a la **IP del VPS** donde estás configurando **gophish**.
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

Comience instalando: `apt-get install postfix`

Luego agregue el dominio a los siguientes archivos:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Cambie también los valores de las siguientes variables dentro de /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Finalmente, modifique los archivos **`/etc/hostname`** y **`/etc/mailname`** con el nombre de su dominio y **reinicie su VPS.**

Ahora, cree un **registro A de DNS** de `mail.<domain>` apuntando a la **dirección IP** del VPS y un **registro MX de DNS** apuntando a `mail.<domain>`

Ahora probemos enviar un correo electrónico:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuración de Gophish**

Detenga la ejecución de Gophish y configuremoslo.\
Modifique `/opt/gophish/config.json` al siguiente (note el uso de https):
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
**Configurar el servicio de gophish**

Para crear el servicio de gophish y que se pueda iniciar automáticamente y gestionar como un servicio, puedes crear el archivo `/etc/init.d/gophish` con el siguiente contenido:
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
Finaliza la configuración del servicio y comprueba que funciona haciendo:
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

### Esperar

Cuanto más antiguo sea un dominio, menos probable es que sea detectado como spam. Por lo tanto, debes esperar tanto tiempo como sea posible (al menos 1 semana) antes de la evaluación de phishing.\
Ten en cuenta que aunque tengas que esperar una semana, puedes terminar de configurar todo ahora.

### Configurar el registro de DNS inverso (rDNS)

Establece un registro de rDNS (PTR) que resuelva la dirección IP del VPS al nombre de dominio.

### Registro de directivas de remitente (SPF)

Debes **configurar un registro SPF para el nuevo dominio**. Si no sabes qué es un registro SPF, [**lee esta página**](../../network-services-pentesting/pentesting-smtp/#spf).

Puedes utilizar [https://www.spfwizard.net/](https://www.spfwizard.net) para generar tu política SPF (utiliza la IP de la máquina VPS)

![](<../../.gitbook/assets/image (388).png>)

Este es el contenido que debe establecerse dentro de un registro TXT dentro del dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro de Autenticación, Informes y Conformidad de Mensajes basados en Dominios (DMARC)

Debe **configurar un registro DMARC para el nuevo dominio**. Si no sabe qué es un registro DMARC, [**lea esta página**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Debe crear un nuevo registro DNS TXT que apunte al nombre de host `_dmarc.<dominio>` con el siguiente contenido:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Debes **configurar un DKIM para el nuevo dominio**. Si no sabes qué es un registro DMARC, [**lee esta página**](../../network-services-pentesting/pentesting-smtp/#dkim).

Este tutorial se basa en: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Debes concatenar ambos valores B64 que genera la clave DKIM:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Prueba la puntuación de configuración de tu correo electrónico

Puedes hacerlo utilizando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Simplemente accede a la página y envía un correo electrónico a la dirección que te proporcionan:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
También puedes **verificar la configuración de tu correo electrónico** enviando un correo electrónico a `check-auth@verifier.port25.com` y **leyendo la respuesta** (para esto necesitarás **abrir** el puerto **25** y ver la respuesta en el archivo _/var/mail/root_ si envías el correo como root).\
Asegúrate de pasar todas las pruebas:
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
Alternativamente, puedes enviar un **mensaje a una dirección de Gmail que controles**, **ver** las **cabeceras del correo electrónico** recibido en tu bandeja de entrada de Gmail, `dkim=pass` debería estar presente en el campo de cabecera `Authentication-Results`.
```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```
### Eliminación de la lista negra de Spamhouse

La página www.mail-tester.com puede indicarte si tu dominio está siendo bloqueado por Spamhouse. Puedes solicitar que se elimine tu dominio/IP en: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Eliminación de la lista negra de Microsoft

Puedes solicitar que se elimine tu dominio/IP en [https://sender.office.com/](https://sender.office.com).

## Crear y lanzar una campaña de GoPhish

### Perfil de envío

* Establece algún **nombre para identificar** el perfil del remitente
* Decide desde qué cuenta vas a enviar los correos electrónicos de phishing. Sugerencias: _noreply, support, servicedesk, salesforce..._
* Puedes dejar en blanco el nombre de usuario y la contraseña, pero asegúrate de marcar la opción Ignorar errores de certificado

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (11).png>)

{% hint style="info" %}
Se recomienda utilizar la funcionalidad "**Enviar correo electrónico de prueba**" para comprobar que todo funciona correctamente.\
Recomendaría **enviar los correos electrónicos de prueba a direcciones de correo electrónico de 10 minutos** para evitar ser incluido en la lista negra durante las pruebas.
{% endhint %}

### Plantilla de correo electrónico

* Establece algún **nombre para identificar** la plantilla
* Luego escribe un **asunto** (nada extraño, solo algo que podrías esperar leer en un correo electrónico normal)
* Asegúrate de haber marcado "**Agregar imagen de seguimiento**"
* Escribe la **plantilla de correo electrónico** (puedes usar variables como en el siguiente ejemplo):
```markup
<html>
<head>
    <title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>

<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">As you may be aware, due to the large number of employees working from home, the "PLATFORM NAME" platform is being migrated to a new domain with an improved and more secure version. To finalize account migration, please use the following link to log into the new HR portal and move your account to the new site: <a href="{{.URL}}"> "PLATFORM NAME" login portal </a><br />
<br />
Please Note: We require all users to move their accounts by 04/01/2021. Failure to confirm account migration may prevent you from logging into the application after the migration process is complete.<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
Nota que **para aumentar la credibilidad del correo electrónico**, se recomienda usar alguna firma de un correo electrónico del cliente. Sugerencias:

* Enviar un correo electrónico a una **dirección inexistente** y comprobar si la respuesta tiene alguna firma.
* Buscar **correos electrónicos públicos** como info@ex.com o press@ex.com o public@ex.com y enviarles un correo electrónico y esperar la respuesta.
* Intentar contactar algún correo electrónico **válido descubierto** y esperar la respuesta.

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
La plantilla de correo electrónico también permite **adjuntar archivos para enviar**. Si también desea robar desafíos NTLM utilizando algunos archivos/documentos especialmente diseñados, [lea esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Página de destino

* Escribir un **nombre**
* **Escribir el código HTML** de la página web. Tenga en cuenta que puede **importar** páginas web.
* Marcar **Capturar datos enviados** y **Capturar contraseñas**
* Establecer una **redirección**

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Por lo general, deberá modificar el código HTML de la página y realizar algunas pruebas en local (tal vez usando algún servidor Apache) **hasta que le gusten los resultados**. Luego, escriba ese código HTML en el cuadro.\
Tenga en cuenta que si necesita **usar algunos recursos estáticos** para el HTML (tal vez algunas páginas CSS y JS) puede guardarlos en _**/opt/gophish/static/endpoint**_ y luego acceder a ellos desde _**/static/\<filename>**_
{% endhint %}

{% hint style="info" %}
Para la redirección, podría **redirigir a los usuarios a la página web principal legítima** de la víctima, o redirigirlos a _/static/migration.html_ por ejemplo, poner una **rueda giratoria (**[**https://loading.io/**](https://loading.io)**) durante 5 segundos y luego indicar que el proceso fue exitoso**.
{% endhint %}

### Usuarios y grupos

* Establecer un nombre
* **Importar los datos** (tenga en cuenta que para usar la plantilla para el ejemplo, necesita el nombre, apellido y dirección de correo electrónico de cada usuario)

![](<../../.gitbook/assets/image (395).png>)

### Campaña

Finalmente, cree una campaña seleccionando un nombre, la plantilla de correo electrónico, la página de destino, la URL, el perfil de envío y el grupo. Tenga en cuenta que la URL será el enlace enviado a las víctimas.

Tenga en cuenta que el **perfil de envío permite enviar un correo electrónico de prueba para ver cómo se verá el correo electrónico de phishing final**:

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
Recomendaría **enviar los correos electrónicos de prueba a direcciones de correo electrónico de 10 minutos** para evitar ser bloqueado haciendo pruebas.
{% endhint %}

¡Una vez que todo esté listo, simplemente lance la campaña!

## Clonación de sitios web

Si por alguna razón desea clonar el sitio web, consulte la siguiente página:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Documentos y archivos con puerta trasera

En algunas evaluaciones de phishing (principalmente para equipos rojos), también querrá **enviar archivos que contengan algún tipo de puerta trasera** (tal vez un C2 o tal vez algo que desencadene una autenticación).\
Consulte la siguiente página para ver algunos ejemplos:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### A través de Proxy MitM

El ataque anterior es bastante inteligente ya que está falsificando un sitio web real y recopilando la información establecida por el usuario. Desafortunadamente, si el usuario no puso la contraseña correcta o si la aplicación que falsificó está configurada con 2FA, **esta información no le permitirá suplantar al usuario engañado**.

Es aquí donde herramientas como [**evilginx2**](https://github.com/kgretzky/evilginx2) o [**CredSniper**](https://github.com/ustayready/CredSniper) son útiles. Esta herramienta le permitirá generar un ataque similar a MitM. Básicamente, el ataque funciona de la siguiente manera:

1. Usted **suplanta el formulario de inicio de sesión** de la página web real.
2. El usuario **envía** sus **credenciales** a su página falsa y la herramienta las envía a la página web real, **comprobando si las credenciales funcionan**.
3. Si la cuenta está configurada con **2FA**, la página MitM lo solicitará y una vez que el **usuario lo introduzca**, la herramienta lo enviará a la página web real.
4. Una vez que el usuario está autenticado, usted (como atacante) habrá **capturado las credenciales, el 2FA, la cookie y cualquier información** de cada interacción mientras la herramienta realiza un MitM.

### A través de VNC

¿Qué pasa si en lugar de **enviar a la víctima a una página maliciosa** con el mismo aspecto que la original, lo envía a una **sesión VNC con un navegador conectado a la página web real**? Podrá ver lo que hace, robar la contraseña, el MFA utilizado, las cookies...\
Puede hacer esto con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detectando la detección

Obviamente, una de las mejores formas de saber si ha sido descubierto es **buscar su dominio en listas negras**. Si aparece en la lista, de alguna manera se detectó su dominio como sospechoso.\
Una forma sencilla de comprobar si su dominio aparece en alguna lista negra es utilizar [https://malwareworld.com/](https://malwareworld.com)

Sin embargo, hay otras formas de saber si la víctima está **buscando activamente actividad de phishing sospechosa en la red** como se explica en:

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Puede **comprar un dominio con un nombre muy similar** al del dominio de la víctima y/o generar un certificado para un **subdominio** de un dominio controlado por usted **que contenga** la **palabra clave** del dominio de la víctima. Si la **víctima** realiza algún tipo de **interacción DNS o HTTP** con ellos, sabrá que **está buscando activamente** dominios sospechosos y deberá ser muy sigiloso.

### Evaluar el phishing

Use [**Phishious** ](https://github.com/Rices/Phishious)para evaluar si su correo electrónico terminará en la carpeta de spam o si será bloqueado o exitoso.

## Referencias

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks
