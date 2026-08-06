# Suricata ve Iptables cheatsheet

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Zincirler

iptables'te zincir olarak bilinen kural listeleri sıralı şekilde işlenir. Bunlar arasında üç temel zincir her zaman bulunur; NAT gibi ek zincirler ise sistemin yeteneklerine bağlı olarak desteklenebilir.

- **Input Chain**: Gelen bağlantıların davranışını yönetmek için kullanılır.
- **Forward Chain**: Yerel sisteme yönelik olmayan gelen bağlantıları işlemek için kullanılır. Bu, alınan verilerin başka bir hedefe yönlendirilmesinin gerektiği router olarak çalışan cihazlarda yaygındır. Bu zincir esas olarak sistem routing, NATing veya benzer işlemlerle ilgilendiğinde kullanılır.
- **Output Chain**: Giden bağlantıların düzenlenmesi için kullanılır.

Bu zincirler, network trafiğinin düzenli şekilde işlenmesini sağlar ve verilerin bir sisteme girişini, sistem içinden geçişini ve sistemden çıkışını yöneten ayrıntılı kuralların belirlenmesine olanak tanır.
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

### Kurulum ve Yapılandırma
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
### Kural Tanımları

[Belgelerden:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Bir kural/imza aşağıdakilerden oluşur:

- **eylem**, imza eşleştiğinde ne olacağını belirler.
- **başlık**, kuralın protokolünü, IP adreslerini, portlarını ve yönünü tanımlar.
- **kural seçenekleri**, kuralın ayrıntılarını tanımlar.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Geçerli action'lar**

- alert - bir alert oluştur
- pass - paketin daha fazla incelenmesini durdur
- **drop** - paketi drop et ve alert oluştur
- **reject** - eşleşen paketin göndericisine RST/ICMP erişilemezlik hatası gönder.
- rejectsrc - yalnızca _reject_ ile aynı
- rejectdst - eşleşen paketin alıcısına RST/ICMP hata paketi gönder.
- rejectboth - iletişimin her iki tarafına da RST/ICMP hata paketleri gönder.

#### **Protokoller**

- tcp (tcp-trafiği için)
- udp
- icmp
- ip (ip, ‘all’ veya ‘any’ anlamına gelir)
- _layer7 protokolleri_: http, ftp, tls, smb, dns, ssh... (daha fazlası [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html) bölümünde)

#### Kaynak ve Hedef Adresler

IP aralıklarını, olumsuzlamaları ve adres listelerini destekler:

| Örnek                        | Anlamı                                  |
| ---------------------------- | --------------------------------------- |
| ! 1.1.1.1                    | 1.1.1.1 dışındaki tüm IP adresleri      |
| !\[1.1.1.1, 1.1.1.2]         | 1.1.1.1 ve 1.1.1.2 dışındaki tüm IP adresleri |
| $HOME_NET                    | yaml içindeki HOME_NET ayarınız         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET ve HOME_NET değil          |
| \[10.0.0.0/24, !10.0.0.5]    | 10.0.0.5 hariç 10.0.0.0/24              |

#### Kaynak ve Hedef Portlar

Port aralıklarını, olumsuzlamaları ve port listelerini destekler.

| Örnek          | Anlamı                               |
| -------------- | ------------------------------------ |
| any            | herhangi bir adres                  |
| \[80, 81, 82]  | 80, 81 ve 82 portları               |
| \[80: 82]      | 80 ile 82 arasındaki aralık          |
| \[1024: ]      | 1024'ten en yüksek port numarasına kadar |
| !80            | 80 dışındaki tüm portlar             |
| \[80:100,!99]  | 99 hariç 80 ile 100 arasındaki aralık |
| \[1:80,!\[2,4]] | 2 ve 4 portları hariç 1-80 aralığı   |

#### Yön

Uygulanan communication rule'un iletişim yönünü belirtmek mümkündür:
```
source -> destination
source <> destination  (both directions)
```
#### Keywords

Suricata'da aradığınız **belirli paketi** bulmak için kullanılabilecek **yüzlerce seçenek** vardır; burada ilginç bir şey bulunursa bundan bahsedilecektir. Daha fazlası için [**belgelere** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) göz atın!
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
