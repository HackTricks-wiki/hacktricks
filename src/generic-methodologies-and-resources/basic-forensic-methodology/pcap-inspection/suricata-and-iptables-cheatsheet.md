# Suricata & Iptables cheatsheet

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chaînes

Dans iptables, des listes de règles connues sous le nom de chaînes sont traitées séquentiellement. Parmi celles-ci, trois chaînes principales sont universellement présentes, avec d'autres comme NAT pouvant être prises en charge en fonction des capacités du système.

- **Chaîne d'entrée** : Utilisée pour gérer le comportement des connexions entrantes.
- **Chaîne de transfert** : Employée pour traiter les connexions entrantes qui ne sont pas destinées au système local. Cela est typique pour les appareils agissant en tant que routeurs, où les données reçues doivent être transférées vers une autre destination. Cette chaîne est pertinente principalement lorsque le système est impliqué dans le routage, le NAT ou des activités similaires.
- **Chaîne de sortie** : Dédiée à la régulation des connexions sortantes.

Ces chaînes garantissent le traitement ordonné du trafic réseau, permettant la spécification de règles détaillées régissant le flux de données dans, à travers et hors d'un système.
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

### Installer et configurer
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
### Définitions des Règles

[From the docs:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Une règle/siganture se compose des éléments suivants :

- L'**action**, détermine ce qui se passe lorsque la signature correspond.
- L'**en-tête**, définit le protocole, les adresses IP, les ports et la direction de la règle.
- Les **options de règle**, définissent les spécificités de la règle.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Les actions valides sont**

- alert - générer une alerte
- pass - arrêter l'inspection supplémentaire du paquet
- **drop** - supprimer le paquet et générer une alerte
- **reject** - envoyer une erreur RST/ICMP injoignable à l'expéditeur du paquet correspondant.
- rejectsrc - identique à _reject_
- rejectdst - envoyer un paquet d'erreur RST/ICMP au destinataire du paquet correspondant.
- rejectboth - envoyer des paquets d'erreur RST/ICMP aux deux côtés de la conversation.

#### **Protocoles**

- tcp (pour le trafic tcp)
- udp
- icmp
- ip (ip signifie 'tous' ou 'n'importe quel')
- _protocoles de couche 7_: http, ftp, tls, smb, dns, ssh... (plus dans la [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Adresses Source et Destination

Il prend en charge les plages d'IP, les négations et une liste d'adresses :

| Exemple                       | Signification                                  |
| ----------------------------- | ---------------------------------------------- |
| ! 1.1.1.1                     | Chaque adresse IP sauf 1.1.1.1                 |
| !\[1.1.1.1, 1.1.1.2]          | Chaque adresse IP sauf 1.1.1.1 et 1.1.1.2     |
| $HOME_NET                     | Votre paramètre de HOME_NET dans yaml          |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET et non HOME_NET                  |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 sauf pour 10.0.0.5                 |

#### Ports Source et Destination

Il prend en charge les plages de ports, les négations et les listes de ports

| Exemple         | Signification                                |
| --------------- | -------------------------------------------- |
| any             | n'importe quelle adresse                     |
| \[80, 81, 82]   | port 80, 81 et 82                            |
| \[80: 82]       | Plage de 80 à 82                             |
| \[1024: ]       | De 1024 jusqu'au numéro de port le plus élevé |
| !80             | Chaque port sauf 80                          |
| \[80:100,!99]   | Plage de 80 à 100 mais 99 exclu             |
| \[1:80,!\[2,4]] | Plage de 1 à 80, sauf les ports 2 et 4      |

#### Direction

Il est possible d'indiquer la direction de la règle de communication appliquée :
```
source -> destination
source <> destination  (both directions)
```
#### Mots-clés

Il y a **des centaines d'options** disponibles dans Suricata pour rechercher le **paquet spécifique** que vous recherchez, ici il sera mentionné si quelque chose d'intéressant est trouvé. Consultez la [**documentation** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) pour plus d'informations !
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
