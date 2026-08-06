# Suricata & Iptables: guia rápido

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chains

No iptables, listas de regras conhecidas como chains são processadas sequencialmente. Entre elas, três chains primárias estão universalmente presentes, enquanto outras, como NAT, podem ser suportadas dependendo dos recursos do sistema.

- **Input Chain**: Utilizada para gerenciar o comportamento das conexões recebidas.
- **Forward Chain**: Utilizada para lidar com conexões recebidas que não são destinadas ao sistema local. Isso é comum em dispositivos que atuam como routers, nos quais os dados recebidos devem ser encaminhados para outro destino. Essa chain é relevante principalmente quando o sistema está envolvido em routing, NATing ou atividades semelhantes.
- **Output Chain**: Dedicada à regulamentação das conexões de saída.

Essas chains garantem o processamento ordenado do tráfego de rede, permitindo a especificação de regras detalhadas que controlam o fluxo de dados para dentro, através e para fora de um sistema.
```bash
# Delete all rules
iptables -F

# List all rules
iptables -L
iptables -S

# Block IP addresses & ports
iptables -I INPUT -s ip1,ip2,ip3 -j DROP
iptables -I INPUT -p tcp --dport 443 -j DROP
iptables -I INPUT -s ip1,ip2 -p tcp --dport 443 -j DROP

# String based drop
## Strings are case sensitive (pretty easy to bypass if you want to check an SQLi for example)
iptables -I INPUT -p tcp --dport <port_listening> -m string --algo bm --string '<payload>' -j DROP
iptables -I OUTPUT -p tcp --sport <port_listening> -m string --algo bm --string 'CTF{' -j DROP
## You can also check for the hex, base64 and double base64 of the expected CTF flag chars

# Drop every input port except some
iptables -P INPUT DROP # Default to drop
iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT


# Persist Iptables
## Debian/Ubuntu:
apt-get install iptables-persistent
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
iptables-restore < /etc/iptables/rules.v4
##RHEL/CentOS:
iptables-save > /etc/sysconfig/iptables
ip6tables-save > /etc/sysconfig/ip6tables
iptables-restore < /etc/sysconfig/iptables
```
## Suricata

### Instalação e Configuração
```bash
# Install details from: https://suricata.readthedocs.io/en/suricata-6.0.0/install.html#install-binary-packages
# Ubuntu
add-apt-repository ppa:oisf/suricata-stable
apt-get update
apt-get install suricata

# Debian
echo "deb http://http.debian.net/debian buster-backports main" > \
/etc/apt/sources.list.d/backports.list
apt-get update
apt-get install suricata -t buster-backports

# CentOS
yum install epel-release
yum install suricata

# Get rules
suricata-update
suricata-update list-sources #List sources of the rules
suricata-update enable-source et/open #Add et/open rulesets
suricata-update
## To use the dowloaded rules update the following line in /etc/suricata/suricata.yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
- suricata.rules

# Run
## Add rules in /etc/suricata/rules/suricata.rules
systemctl suricata start
suricata -c /etc/suricata/suricata.yaml -i eth0


# Reload rules
suricatasc -c ruleset-reload-nonblocking
## or set the follogin in /etc/suricata/suricata.yaml
detect-engine:
- rule-reload: true

# Validate suricata config
suricata -T -c /etc/suricata/suricata.yaml -v

# Configure suricata as IPs
## Config drop to generate alerts
## Search for the following lines in /etc/suricata/suricata.yaml and remove comments:
- drop:
alerts: yes
flows: all

## Forward all packages to the queue where suricata can act as IPS
iptables -I INPUT -j NFQUEUE
iptables -I OUTPUT -j NFQUEUE

## Start suricata in IPS mode
suricata -c /etc/suricata/suricata.yaml  -q 0
### or modify the service config file as:
systemctl edit suricata.service

[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid -q 0 -vvv
Type=simple

systemctl daemon-reload
```
### Definições das regras

[Da documentação:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Uma regra/assinatura consiste no seguinte:

- A **ação** determina o que acontece quando a assinatura corresponde.
- O **cabeçalho** define o protocolo, os endereços IP, as portas e a direção da regra.
- As **opções da regra** definem os detalhes específicos da regra.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Ações válidas são**

- alert - gerar um alerta
- pass - interromper a inspeção adicional do pacote
- **drop** - descartar o pacote e gerar um alerta
- **reject** - enviar um erro RST/ICMP unreachable ao remetente do pacote correspondente.
- rejectsrc - igual a _reject_
- rejectdst - enviar um pacote de erro RST/ICMP ao receptor do pacote correspondente.
- rejectboth - enviar pacotes de erro RST/ICMP para ambos os lados da comunicação.

#### **Protocolos**

- tcp (para tráfego tcp)
- udp
- icmp
- ip (ip significa ‘all’ ou ‘any’)
- _protocolos layer7_: http, ftp, tls, smb, dns, ssh... (mais informações na [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Endereços de origem e destino

É compatível com intervalos de IP, negações e uma lista de endereços:

| Exemplo                       | Significado                                  |
| ----------------------------- | -------------------------------------------- |
| ! 1.1.1.1                     | Todo endereço IP, exceto 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]          | Todo endereço IP, exceto 1.1.1.1 e 1.1.1.2 |
| $HOME_NET                     | Sua configuração de HOME_NET no yaml         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET e não HOME_NET            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24, exceto 10.0.0.5          |

#### Portas de origem e destino

É compatível com intervalos de portas, negações e listas de portas

| Exemplo         | Significado                                |
| --------------- | ------------------------------------------ |
| any             | qualquer endereço                            |
| \[80, 81, 82]   | portas 80, 81 e 82                     |
| \[80: 82]       | Intervalo de 80 até 82                  |
| \[1024: ]       | De 1024 até o maior número de porta |
| !80             | Todas as portas, exceto 80                      |
| \[80:100,!99]   | Intervalo de 80 até 100, exceto 99 |
| \[1:80,!\[2,4]] | Intervalo de 1 a 80, exceto as portas 2 e 4  |

#### Direção

É possível indicar a direção da comunicação à qual a rule está sendo aplicada:
```
source -> destination
source <> destination  (both directions)
```
#### Palavras-chave

Há **centenas de opções** disponíveis no Suricata para procurar o **pacote específico** que você está procurando; aqui, será mencionado se algo interessante for encontrado. Consulte a [**documentação** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) para obter mais informações!
```bash
# Meta Keywords
msg: "description"; #Set a description to the rule
sid:123 #Set a unique ID to the rule
rev:1 #Rule revision number
config classification: not-suspicious,Not Suspicious Traffic,3 #Classify
reference: url, www.info.com #Reference
priority:1; #Set a priority
metadata: key value, key value; #Extra metadata

# Filter by geolocation
geoip: src,RU;

# ICMP type & Code
itype:<10;
icode:0

# Filter by string
content: "something"
content: |61 61 61| #Hex: AAA
content: "http|3A|//" #Mix string and hex
content: "abc"; nocase; #Case insensitive
reject tcp any any -> any any (msg: "php-rce"; content: "eval"; nocase; metadata: tag php-rce; sid:101; rev: 1;)

# Replaces string
## Content and replace string must have the same length
content:"abc"; replace: "def"
alert tcp any any -> any any (msg: "flag replace"; content: "CTF{a6st"; replace: "CTF{u798"; nocase; sid:100; rev: 1;)
## The replace works in both input and output packets
## But it only modifies the first match

# Filter by regex
pcre:"/<regex>/opts"
pcre:"/NICK .*USA.*[0-9]{3,}/i"
drop tcp any any -> any any (msg:"regex"; pcre:"/CTF\{[\w]{3}/i"; sid:10001;)

# Other examples
## Drop by port
drop tcp any any -> any 8000 (msg:"8000 port"; sid:1000;)
```
{{#include ../../../banners/hacktricks-training.md}}
