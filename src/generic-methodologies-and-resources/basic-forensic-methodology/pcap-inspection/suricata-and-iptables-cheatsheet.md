# Suricata & Iptables: folha de consulta

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chains

No iptables, cada chain é uma lista sequencial de regras de correspondência de pacotes. A tabela `filter` padrão contém as chains integradas `INPUT`, `FORWARD` e `OUTPUT`; outras tabelas, como `nat`, podem estar disponíveis dependendo da configuração do kernel e dos módulos carregados.<sup>[[1]](#references)</sup>

- **Input Chain**: Utilizada para gerenciar o comportamento das conexões de entrada.
- **Forward Chain**: Empregada para lidar com conexões de entrada que não se destinam ao sistema local. Isso é típico de dispositivos que atuam como routers, nos quais os dados recebidos devem ser encaminhados para outro destino. Essa chain é relevante principalmente quando o sistema está envolvido em routing, NATing ou atividades semelhantes.
- **Output Chain**: Dedicada à regulamentação das conexões de saída.

Essas chains garantem o processamento ordenado do tráfego de rede, permitindo a especificação de regras detalhadas que governam o fluxo de dados para dentro, através e para fora de um sistema.

Os exemplos de correspondência de strings usam a correspondência padrão `string`; a correspondência diferencia maiúsculas de minúsculas, a menos que `--icase` seja fornecido, e `--algo` seleciona a estratégia de pesquisa BM ou KMP.<sup>[[2]](#references)</sup>
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

Os comandos de pacote abaixo são específicos da distribuição e da versão; o guia oficial de instalação documenta o PPA do Ubuntu, os backports do Debian, os pacotes RPM e o gerenciamento do serviço systemd.<sup>[[3]](#references)</sup>
```bash
# Package installation details vary by distribution and release; see References.
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
suricata-update update-sources
suricata-update list-sources #List sources of the rules
suricata-update enable-source et/open #Add et/open rulesets
suricata-update
## To use the dowloaded rules update the following line in /etc/suricata/suricata.yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
- suricata.rules

# Run
## Add rules in /etc/suricata/rules/suricata.rules
systemctl start suricata
suricata -c /etc/suricata/suricata.yaml -i eth0


# Reload rules
suricatasc -c ruleset-reload-nonblocking

# Validate suricata config
suricata -T -c /etc/suricata/suricata.yaml -v

# Configure Suricata as an IPS
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
A sequência `suricata-update` segue o fluxo de trabalho documentado do Suricata para buscar, listar, habilitar e carregar fontes de regras.<sup>[[4]](#references)</sup> O comando `suricatasc` acima é um método documentado e não bloqueante para recarregar regras por Unix socket.<sup>[[8]](#references)</sup> As regras NFQUEUE enviam o tráfego local de entrada/saída para o Suricata, enquanto `-q 0` seleciona a fila 0 para processamento inline.<sup>[[7]](#references)</sup>

### Definições de regras

Uma regra/assinatura do Suricata tem três partes.<sup>[[5]](#references)</sup>

- A **ação** especifica o que acontece quando a assinatura corresponde.
- O **cabeçalho** seleciona o protocolo, os endereços IP, as portas e a direção.
- As **opções da regra** definem os detalhes específicos da correspondência.
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
- _protocolos de layer7_: http, ftp, tls, smb, dns, ssh e outros.<sup>[[5]](#references)</sup>

#### Endereços de origem e destino

Suricata oferece suporte a intervalos de IP, negação e listas de endereços agrupados.<sup>[[5]](#references)</sup>

| Exemplo                       | Significado                                  |
| ----------------------------- | -------------------------------------------- |
| ! 1.1.1.1                     | Todo endereço IP, exceto 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]          | Todo endereço IP, exceto 1.1.1.1 e 1.1.1.2 |
| $HOME_NET                     | Sua configuração de HOME_NET em yaml         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET e não HOME_NET            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24, exceto 10.0.0.5          |

#### Portas de origem e destino

Suricata oferece suporte a intervalos de portas, negação e listas de portas.<sup>[[5]](#references)</sup>

| Exemplo         | Significado                                |
| --------------- | -------------------------------------- |
| any             | qualquer endereço                            |
| \[80, 81, 82]   | portas 80, 81 e 82                     |
| \[80: 82]       | Intervalo de 80 a 82                  |
| \[1024: ]       | De 1024 até o número de porta mais alto |
| !80             | Todas as portas, exceto a 80                      |
| \[80:100,!99]   | Intervalo de 80 a 100, exceto a 99 |
| \[1:80,!\[2,4]] | Intervalo de 1 a 80, exceto as portas 2 e 4  |

#### Direção

As regras do Suricata podem especificar a direção da comunicação que está sendo avaliada.<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### Palavras-chave

Os exemplos abaixo usam as palavras-chave das regras do Suricata, incluindo opções de metadados, IP, ICMP, payload e camada de aplicação; a documentação oficial das regras cataloga essas famílias e sua sintaxe.<sup>[[6]](#references)[[9]](#references)</sup>
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
## The replace modifier is IPS-only and operates on individual packets
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
## References

- [1] [iptables(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Instalação — documentação do Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Gerenciamento de regras com Suricata-Update — documentação do Suricata 8.0.1](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Formato das regras — documentação do Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Keywords de payload — documentação do Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Configurando IPS/inline para Linux — documentação do Suricata 7.0.15](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Recarregamento de regras — documentação do Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Regras do Suricata — documentação do Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
