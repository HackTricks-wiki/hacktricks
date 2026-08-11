# Aide-mémoire Suricata & Iptables

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chaînes

Dans iptables, chaque chaîne est une liste séquentielle de règles correspondant aux paquets. La table `filter` par défaut contient les chaînes intégrées `INPUT`, `FORWARD` et `OUTPUT` ; d’autres tables, telles que `nat`, peuvent être disponibles selon la configuration du kernel et les modules chargés.<sup>[[1]](#references)</sup>

- **Chaîne Input** : utilisée pour gérer le comportement des connexions entrantes.
- **Chaîne Forward** : utilisée pour gérer les connexions entrantes qui ne sont pas destinées au système local. Cela concerne généralement les appareils agissant comme des routeurs, lorsque les données reçues doivent être transférées vers une autre destination. Cette chaîne est principalement pertinente lorsque le système participe au routage, au NAT ou à des activités similaires.
- **Chaîne Output** : dédiée à la régulation des connexions sortantes.

Ces chaînes assurent le traitement ordonné du trafic réseau et permettent de définir des règles détaillées régissant le flux des données vers un système, à travers celui-ci et depuis celui-ci.

Les exemples de correspondance de chaînes utilisent la correspondance standard `string` ; la correspondance est sensible à la casse, sauf si `--icase` est fourni, et `--algo` sélectionne la stratégie de recherche BM ou KMP.<sup>[[2]](#references)</sup>
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

### Installation et configuration

Les commandes des paquets ci-dessous dépendent de la distribution et de la version ; le guide d’installation officiel documente le PPA Ubuntu, les backports Debian, les paquets RPM et la gestion du service systemd.<sup>[[3]](#references)</sup>
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
La séquence `suricata-update` suit le workflow documenté de Suricata pour récupérer, répertorier, activer et charger les sources de règles.<sup>[[4]](#references)</sup> La commande `suricatasc` ci-dessus est une méthode documentée de rechargement non bloquant des règles via un socket Unix.<sup>[[8]](#references)</sup> Les règles NFQUEUE envoient le trafic local entrant et sortant vers Suricata, tandis que `-q 0` sélectionne la file d’attente 0 pour le traitement inline.<sup>[[7]](#references)</sup>

### Définitions des règles

Une règle ou signature Suricata comporte trois parties.<sup>[[5]](#references)</sup>

- L’**action** indique ce qui se produit lorsque la signature correspond.
- L’**en-tête** sélectionne le protocole, les adresses IP, les ports et la direction.
- Les **options de la règle** définissent les détails spécifiques à la correspondance.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Les actions valides sont**

- alert - générer une alerte
- pass - arrêter toute inspection supplémentaire du paquet
- **drop** - supprimer le paquet et générer une alerte
- **reject** - envoyer une erreur RST/ICMP unreachable à l’expéditeur du paquet correspondant.
- rejectsrc - identique à _reject_
- rejectdst - envoyer un paquet d’erreur RST/ICMP au destinataire du paquet correspondant.
- rejectboth - envoyer des paquets d’erreur RST/ICMP aux deux côtés de la conversation.

#### **Protocoles**

- tcp (pour le trafic tcp)
- udp
- icmp
- ip (ip signifie « all » ou « any »)
- _protocoles layer7_ : http, ftp, tls, smb, dns, ssh, et autres.<sup>[[5]](#references)</sup>

#### Adresses source et destination

Suricata prend en charge les plages d’adresses IP, la négation et les listes d’adresses groupées.<sup>[[5]](#references)</sup>

| Exemple                       | Signification                                  |
| ----------------------------- | ---------------------------------------------- |
| ! 1.1.1.1                     | Toute adresse IP sauf 1.1.1.1                  |
| !\[1.1.1.1, 1.1.1.2]          | Toute adresse IP sauf 1.1.1.1 et 1.1.1.2      |
| $HOME_NET                     | Votre configuration de HOME_NET dans yaml      |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET et non HOME_NET                   |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 à l’exception de 10.0.0.5         |

#### Ports source et destination

Suricata prend en charge les plages de ports, la négation et les listes de ports.<sup>[[5]](#references)</sup>

| Exemple         | Signification                         |
| --------------- | ------------------------------------- |
| any             | toute adresse                         |
| \[80, 81, 82]   | ports 80, 81 et 82                    |
| \[80: 82]       | Plage de 80 à 82                      |
| \[1024: ]       | De 1024 au numéro de port le plus élevé |
| !80             | Tous les ports sauf le port 80        |
| \[80:100,!99]   | Plage de 80 à 100, sauf le port 99    |
| \[1:80,!\[2,4]] | Plage de 1 à 80, sauf les ports 2 et 4 |

#### Direction

Les règles Suricata peuvent spécifier la direction de la communication évaluée.<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### Mots-clés

Les exemples ci-dessous utilisent les mots-clés de règles de Suricata, notamment les options de métadonnées, IP, ICMP, payload et de la couche application ; la documentation officielle des règles répertorie ces familles et leur syntaxe.<sup>[[6]](#references)[[9]](#references)</sup>
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

- [1] [iptables(8) — page du manuel Linux](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — page du manuel Linux](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Installation — documentation de Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Gestion des règles avec Suricata-Update — documentation de Suricata 8.0.1](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Format des règles — documentation de Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Mots-clés de payload — documentation de Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Configuration d’IPS/inline pour Linux — documentation de Suricata 7.0.15](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Rechargement des règles — documentation de Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Règles Suricata — documentation de Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
