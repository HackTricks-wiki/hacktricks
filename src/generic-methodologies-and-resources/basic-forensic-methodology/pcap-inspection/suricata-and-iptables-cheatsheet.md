# Suricata & Iptables cheatsheet

## Iptables

### Catene

In iptables, ogni catena è un elenco sequenziale di regole che verificano la corrispondenza dei pacchetti. La tabella `filter` predefinita include le catene integrate `INPUT`, `FORWARD` e `OUTPUT`; altre tabelle, come `nat`, possono essere disponibili a seconda della configurazione del kernel e dei moduli caricati.<sup>[[1]](#references)</sup>

- **Catena Input**: Utilizzata per gestire il comportamento delle connessioni in entrata.
- **Catena Forward**: Utilizzata per gestire le connessioni in entrata che non sono destinate al sistema locale. Questo è tipico dei dispositivi che fungono da router, dove i dati ricevuti devono essere inoltrati verso un'altra destinazione. Questa catena è rilevante principalmente quando il sistema è coinvolto in attività di routing, NATing o simili.
- **Catena Output**: Dedicata alla regolamentazione delle connessioni in uscita.

Queste catene garantiscono l'elaborazione ordinata del traffico di rete, consentendo di specificare regole dettagliate che disciplinano il flusso dei dati verso, attraverso e fuori da un sistema.

Gli esempi di string-match utilizzano il match standard `string`; la corrispondenza distingue tra maiuscole e minuscole, a meno che non venga fornito `--icase`, mentre `--algo` seleziona la strategia di ricerca BM o KMP.<sup>[[2]](#references)</sup>
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

### Installazione e configurazione

I comandi per i pacchetti variano in base alla distribuzione e alla release; la guida ufficiale all'installazione documenta il PPA di Ubuntu, i backport di Debian, i pacchetti RPM e la gestione dei servizi systemd.<sup>[[3]](#references)</sup>
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
La sequenza `suricata-update` segue il workflow documentato di Suricata per recuperare, elencare, abilitare e caricare le sorgenti delle regole.<sup>[[4]](#references)</sup> Il comando `suricatasc` sopra riportato è un metodo documentato non bloccante per ricaricare le regole tramite Unix-socket.<sup>[[8]](#references)</sup> Le regole NFQUEUE inviano il traffico locale in entrata e in uscita a Suricata, mentre `-q 0` seleziona la queue 0 per l'elaborazione inline.<sup>[[7]](#references)</sup>

### Definizioni delle regole

Una regola/firma di Suricata è composta da tre parti.<sup>[[5]](#references)</sup>

- L'**azione** specifica cosa accade quando la firma corrisponde.
- L'**header** seleziona il protocollo, gli indirizzi IP, le porte e la direzione.
- Le **opzioni della regola** definiscono i dettagli specifici della corrispondenza.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Le azioni valide sono**

- alert - genera un alert
- pass - interrompe l'ispezione ulteriore del pacchetto
- **drop** - scarta il pacchetto e genera un alert
- **reject** - invia un errore RST/ICMP unreachable al mittente del pacchetto corrispondente.
- rejectsrc - come _reject_
- rejectdst - invia un pacchetto di errore RST/ICMP al destinatario del pacchetto corrispondente.
- rejectboth - invia pacchetti di errore RST/ICMP a entrambi i lati della conversazione.

#### **Protocolli**

- tcp (per il traffico tcp)
- udp
- icmp
- ip (ip significa "all" o "any")
- _protocolli layer7_: http, ftp, tls, smb, dns, ssh e altri.<sup>[[5]](#references)</sup>

#### Indirizzi di origine e destinazione

Suricata supporta intervalli di indirizzi IP, negazione ed elenchi di indirizzi raggruppati.<sup>[[5]](#references)</sup>

| Esempio                      | Significato                                  |
| ---------------------------- | -------------------------------------------- |
| ! 1.1.1.1                    | Ogni indirizzo IP tranne 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]         | Ogni indirizzo IP tranne 1.1.1.1 e 1.1.1.2  |
| $HOME_NET                    | La tua impostazione di HOME_NET in yaml      |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET e non HOME_NET                 |
| \[10.0.0.0/24, !10.0.0.5]    | 10.0.0.0/24 ad eccezione di 10.0.0.5         |

#### Porte di origine e destinazione

Suricata supporta intervalli di porte, negazione ed elenchi di porte.<sup>[[5]](#references)</sup>

| Esempio        | Significato                              |
| -------------- | ---------------------------------------- |
| any            | qualsiasi indirizzo                     |
| \[80, 81, 82]  | porte 80, 81 e 82                        |
| \[80: 82]      | Intervallo da 80 a 82                    |
| \[1024: ]      | Da 1024 fino al numero di porta massimo |
| !80            | Ogni porta tranne la 80                 |
| \[80:100,!99]  | Intervallo da 80 a 100, esclusa la 99   |
| \[1:80,!\[2,4]] | Intervallo da 1 a 80, ad eccezione delle porte 2 e 4 |

#### Direzione

Le regole di Suricata possono specificare la direzione della comunicazione valutata.<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### Parole chiave

Gli esempi seguenti utilizzano i keyword delle regole di Suricata, inclusi metadati, IP, ICMP, payload e opzioni del livello applicativo; la documentazione ufficiale delle regole elenca queste categorie e la relativa sintassi.<sup>[[6]](#references)[[9]](#references)</sup>
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

- [1] [iptables(8) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Installazione — documentazione di Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Gestione delle regole con Suricata-Update — documentazione di Suricata 8.0.1](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Formato delle regole — documentazione di Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Keyword del payload — documentazione di Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Configurazione di IPS/inline per Linux — documentazione di Suricata 7.0.15](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Ricaricamento delle regole — documentazione di Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Regole di Suricata — documentazione di Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
