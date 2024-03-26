# Metodología de Phishing

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Metodología

1. Reconocer a la víctima
1. Seleccionar el **dominio de la víctima**.
2. Realizar una enumeración web básica **buscando portales de inicio de sesión** utilizados por la víctima y **decidir** cuál vas a **suplantar**.
3. Utilizar algo de **OSINT** para **encontrar correos electrónicos**.
2. Preparar el entorno
1. **Comprar el dominio** que vas a utilizar para la evaluación de phishing.
2. **Configurar el servicio de correo electrónico** relacionado con los registros (SPF, DMARC, DKIM, rDNS)
3. Configurar el VPS con **gophish**
3. Preparar la campaña
1. Preparar la **plantilla de correo electrónico**
2. Preparar la **página web** para robar las credenciales
4. ¡Lanzar la campaña!

## Generar nombres de dominio similares o comprar un dominio de confianza

### Técnicas de Variación de Nombres de Dominio

* **Palabra clave**: El nombre de dominio **contiene** una **palabra clave** importante del dominio original (por ejemplo, zelster.com-management.com).
* **Subdominio con guion**: Cambiar el **punto por un guion** de un subdominio (por ejemplo, www-zelster.com).
* **Nuevo TLD**: Mismo dominio usando un **nuevo TLD** (por ejemplo, zelster.org)
* **Homóglifo**: Se **reemplaza** una letra en el nombre de dominio con **letras que se ven similares** (por ejemplo, zelfser.com).
* **Transposición:** Se **intercambian dos letras** dentro del nombre de dominio (por ejemplo, zelsetr.com).
* **Singularización/Pluralización**: Agrega o elimina la "s" al final del nombre de dominio (por ejemplo, zeltsers.com).
* **Omisión**: Se **elimina una** de las letras del nombre de dominio (por ejemplo, zelser.com).
* **Repetición**: Se **repite una** de las letras en el nombre de dominio (por ejemplo, zeltsser.com).
* **Reemplazo**: Similar al homóglifo pero menos sigiloso. Reemplaza una de las letras en el nombre de dominio, quizás con una letra en proximidad de la letra original en el teclado (por ejemplo, zektser.com).
* **Subdominado**: Introduce un **punto** dentro del nombre de dominio (por ejemplo, ze.lster.com).
* **Inserción**: Se **inserta una letra** en el nombre de dominio (por ejemplo, zerltser.com).
* **Punto faltante**: Agregar el TLD al nombre de dominio. (por ejemplo, zelstercom.com)

**Herramientas Automáticas**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sitios web**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Existe la **posibilidad de que uno de algunos bits almacenados o en comunicación se invierta automáticamente** debido a varios factores como llamaradas solares, rayos cósmicos o errores de hardware.

Cuando este concepto se **aplica a las solicitudes DNS**, es posible que el **dominio recibido por el servidor DNS** no sea el mismo que el dominio solicitado inicialmente.

Por ejemplo, una modificación de un solo bit en el dominio "windows.com" puede cambiarlo a "windnws.com."

Los atacantes pueden **aprovechar esto registrando múltiples dominios con inversión de bits** que sean similares al dominio de la víctima. Su intención es redirigir a los usuarios legítimos a su propia infraestructura.

Para obtener más información, lee [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Comprar un dominio de confianza

Puedes buscar en [https://www.expireddomains.net/](https://www.expireddomains.net) un dominio caducado que podrías utilizar.\
Para asegurarte de que el dominio caducado que vas a comprar **ya tiene un buen SEO** podrías buscar cómo está categorizado en:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Descubriendo Correos Electrónicos

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratis)
* [https://phonebook.cz/](https://phonebook.cz) (100% gratis)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Para **descubrir más** direcciones de correo electrónico válidas o **verificar las que** ya has descubierto, puedes verificar si puedes hacer fuerza bruta en los servidores smtp de la víctima. [Aprende cómo verificar/descubrir direcciones de correo electrónico aquí](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Además, no olvides que si los usuarios utilizan **cualquier portal web para acceder a sus correos electrónicos**, puedes verificar si es vulnerable a **fuerza bruta de nombres de usuario**, y explotar la vulnerabilidad si es posible.

## Configurando GoPhish

### Instalación

Puedes descargarlo desde [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Descárgalo y descomprímelo dentro de `/opt/gophish` y ejecuta `/opt/gophish/gophish`\
Se te dará una contraseña para el usuario administrador en el puerto 3333 en la salida. Por lo tanto, accede a ese puerto y usa esas credenciales para cambiar la contraseña del administrador. Es posible que necesites hacer un túnel de ese puerto a local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuración

**Configuración del certificado TLS**

Antes de este paso, debes **haber comprado el dominio** que vas a utilizar y este debe estar **apuntando** a la **IP del VPS** donde estás configurando **gophish**.
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

`myhostname = <dominio>`\
`mydestination = $myhostname, <dominio>, localhost.com, localhost`

Finalmente, modifique los archivos **`/etc/hostname`** y **`/etc/mailname`** con el nombre de su dominio y **reinicie su VPS.**

Ahora, cree un **registro A de DNS** de `mail.<dominio>` apuntando a la **dirección IP** del VPS y un **registro MX de DNS** apuntando a `mail.<dominio>`

Ahora probemos enviar un correo electrónico:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuración de Gophish**

Detenga la ejecución de gophish y configuremos.\
Modifique `/opt/gophish/config.json` al siguiente (nota el uso de https):
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

Para crear el servicio de gophish para que se inicie automáticamente y se pueda gestionar como un servicio, puedes crear el archivo `/etc/init.d/gophish` con el siguiente contenido:
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
Termina de configurar el servicio y verifica que funcione haciendo:
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

Cuanto más antiguo sea un dominio, menos probable es que sea detectado como spam. Por lo tanto, debes esperar tanto tiempo como sea posible (al menos 1 semana) antes de la evaluación de phishing. Además, si colocas una página sobre un sector reputacional, la reputación obtenida será mejor.

Ten en cuenta que aunque tengas que esperar una semana, puedes terminar de configurarlo todo ahora.

### Configurar el registro de DNS inverso (rDNS)

Establece un registro rDNS (PTR) que resuelva la dirección IP del VPS al nombre de dominio.

### Registro del Marco de Políticas del Remitente (SPF)

Debes **configurar un registro SPF para el nuevo dominio**. Si no sabes qué es un registro SPF, [**lee esta página**](../../network-services-pentesting/pentesting-smtp/#spf).

Puedes utilizar [https://www.spfwizard.net/](https://www.spfwizard.net) para generar tu política SPF (utiliza la IP de la máquina VPS)

![](<../../.gitbook/assets/image (388).png>)

Este es el contenido que debe establecerse dentro de un registro TXT dentro del dominio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro de Autenticación de Mensajes Basado en Dominio, Informes y Conformidad (DMARC)

Debes **configurar un registro DMARC para el nuevo dominio**. Si no sabes qué es un registro DMARC, [**lee esta página**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Debes crear un nuevo registro DNS TXT apuntando al nombre de host `_dmarc.<dominio>` con el siguiente contenido:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Debes **configurar un DKIM para el nuevo dominio**. Si no sabes qué es un registro DMARC, [**lee esta página**](../../network-services-pentesting/pentesting-smtp/#dkim).

Este tutorial está basado en: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Necesitas concatenar ambos valores B64 que genera la clave DKIM:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Prueba tu puntuación de configuración de correo electrónico

Puedes hacerlo usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Simplemente accede a la página y envía un correo electrónico a la dirección que te proporcionan:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
También puedes **verificar la configuración de tu correo electrónico** enviando un correo electrónico a `check-auth@verifier.port25.com` y **leyendo la respuesta** (para esto necesitarás **abrir** el puerto **25** y ver la respuesta en el archivo _/var/mail/root_ si envías el correo como root).\
Verifica que pasas todas las pruebas:
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
También puedes enviar **un mensaje a un Gmail bajo tu control** y verificar los **encabezados del correo electrónico** en tu bandeja de entrada de Gmail, `dkim=pass` debería estar presente en el campo de encabezado `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Eliminación de la lista negra de Spamhouse

La página [www.mail-tester.com](www.mail-tester.com) puede indicarte si tu dominio está siendo bloqueado por Spamhouse. Puedes solicitar que tu dominio/IP sea eliminado en: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Eliminación de la lista negra de Microsoft

Puedes solicitar que tu dominio/IP sea eliminado en [https://sender.office.com/](https://sender.office.com).

## Crear y Lanzar una Campaña de GoPhish

### Perfil de Envío

* Establece un **nombre para identificar** el perfil del remitente
* Decide desde qué cuenta vas a enviar los correos de phishing. Sugerencias: _noreply, support, servicedesk, salesforce..._
* Puedes dejar en blanco el nombre de usuario y la contraseña, pero asegúrate de marcar la opción Ignorar Errores de Certificado

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
Se recomienda utilizar la funcionalidad "**Enviar Correo de Prueba**" para verificar que todo funcione correctamente.\
Recomendaría **enviar los correos de prueba a direcciones de correo de 10 minutos** para evitar ser incluido en listas negras al hacer pruebas.
{% endhint %}

### Plantilla de Correo Electrónico

* Establece un **nombre para identificar** la plantilla
* Luego escribe un **asunto** (nada extraño, solo algo que esperarías leer en un correo electrónico regular)
* Asegúrate de marcar "**Agregar Imagen de Seguimiento**"
* Escribe la **plantilla de correo electrónico** (puedes usar variables como en el siguiente ejemplo):
```markup
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
Tenga en cuenta que **para aumentar la credibilidad del correo electrónico**, se recomienda utilizar alguna firma de un correo electrónico del cliente. Sugerencias:

* Enviar un correo electrónico a una **dirección inexistente** y verificar si la respuesta tiene alguna firma.
* Buscar correos electrónicos **públicos** como info@ejemplo.com o prensa@ejemplo.com o publico@ejemplo.com y enviarles un correo electrónico y esperar la respuesta.
* Intentar contactar un correo electrónico **válido descubierto** y esperar la respuesta.

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
La Plantilla de Correo Electrónico también permite **adjuntar archivos para enviar**. Si también desea robar desafíos NTLM utilizando archivos/documentos especialmente creados, [lea esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Página de Aterrizaje

* Escriba un **nombre**
* **Escriba el código HTML** de la página web. Tenga en cuenta que puede **importar** páginas web.
* Marque **Capturar Datos Enviados** y **Capturar Contraseñas**
* Establezca una **redirección**

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Por lo general, necesitará modificar el código HTML de la página y realizar algunas pruebas localmente (quizás utilizando un servidor Apache) **hasta que le gusten los resultados**. Luego, escriba ese código HTML en el cuadro.\
Tenga en cuenta que si necesita **utilizar algunos recursos estáticos** para el HTML (quizás algunas páginas CSS y JS) puede guardarlos en _**/opt/gophish/static/endpoint**_ y luego acceder a ellos desde _**/static/\<nombrearchivo>**_
{% endhint %}

{% hint style="info" %}
Para la redirección, podría **redirigir a los usuarios a la página web principal legítima** de la víctima, o redirigirlos a _/static/migration.html_ por ejemplo, poner una **rueda giratoria (**[**https://loading.io/**](https://loading.io)**) durante 5 segundos y luego indicar que el proceso fue exitoso**.
{% endhint %}

### Usuarios y Grupos

* Establezca un nombre
* **Importe los datos** (tenga en cuenta que para usar la plantilla del ejemplo necesita el nombre, apellido y dirección de correo electrónico de cada usuario)

![](<../../.gitbook/assets/image (395).png>)

### Campaña

Finalmente, cree una campaña seleccionando un nombre, la plantilla de correo electrónico, la página de aterrizaje, la URL, el perfil de envío y el grupo. Tenga en cuenta que la URL será el enlace enviado a las víctimas

Tenga en cuenta que el **Perfil de Envío permite enviar un correo electrónico de prueba para ver cómo se verá el correo electrónico de phishing final**:

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
Recomendaría **enviar los correos de prueba a direcciones de correo de 10 minutos** para evitar ser incluido en listas negras al hacer pruebas.
{% endhint %}

¡Una vez que todo esté listo, simplemente lance la campaña!

## Clonación de Sitios Web

Si por alguna razón desea clonar el sitio web, consulte la siguiente página:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Documentos y Archivos con Puertas Traseras

En algunas evaluaciones de phishing (principalmente para Equipos Rojos) también querrá **enviar archivos que contengan algún tipo de puerta trasera** (tal vez un C2 o simplemente algo que active una autenticación).\
Consulte la siguiente página para ver algunos ejemplos:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### A través de Proxy MitM

El ataque anterior es bastante astuto, ya que está falsificando un sitio web real y recopilando la información establecida por el usuario. Desafortunadamente, si el usuario no ingresó la contraseña correcta o si la aplicación que falsificó está configurada con 2FA, **esta información no le permitirá suplantar al usuario engañado**.

Aquí es donde herramientas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) y [**muraena**](https://github.com/muraenateam/muraena) son útiles. Esta herramienta le permitirá generar un ataque tipo MitM. Básicamente, los ataques funcionan de la siguiente manera:

1. **Suplantas el formulario de inicio de sesión** de la página web real.
2. El usuario **envía** sus **credenciales** a tu página falsa y la herramienta las envía a la página real, **verificando si las credenciales funcionan**.
3. Si la cuenta está configurada con **2FA**, la página MitM solicitará esto y una vez que el **usuario lo introduzca**, la herramienta lo enviará a la página web real.
4. Una vez que el usuario esté autenticado, tú (como atacante) habrás **capturado las credenciales, el 2FA, la cookie y cualquier información** de cada interacción mientras la herramienta realiza un MitM.

### A través de VNC

¿Qué tal si en lugar de **enviar a la víctima a una página maliciosa** con el mismo aspecto que la original, la envías a una **sesión VNC con un navegador conectado al sitio web real**? Podrás ver lo que hace, robar la contraseña, el MFA utilizado, las cookies...\
Puedes hacer esto con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detectando la Detección

Obviamente, una de las mejores formas de saber si te han descubierto es **buscar tu dominio en listas negras**. Si aparece listado, de alguna manera tu dominio fue detectado como sospechoso.\
Una forma sencilla de verificar si tu dominio aparece en alguna lista negra es utilizando [https://malwareworld.com/](https://malwareworld.com)

Sin embargo, hay otras formas de saber si la víctima está **buscando activamente actividad de phishing sospechosa en la red** como se explica en:

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Puedes **comprar un dominio con un nombre muy similar** al del dominio de la víctima y/o generar un certificado para un **subdominio** de un dominio controlado por ti **que contenga** la **palabra clave** del dominio de la víctima. Si la **víctima** realiza algún tipo de **interacción DNS o HTTP** con ellos, sabrás que **está buscando activamente** dominios sospechosos y deberás ser muy sigiloso.

### Evaluar el Phishing

Utiliza [**Phishious** ](https://github.com/Rices/Phishious)para evaluar si tu correo electrónico terminará en la carpeta de spam o si será bloqueado o exitoso.

## Referencias

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
* [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
