# Suricata & Iptables kısa notları

## Iptables

### Chains

iptables'te her chain, paketlerle eşleşen kuralların sıralı bir listesidir. Varsayılan `filter` tablosunda yerleşik `INPUT`, `FORWARD` ve `OUTPUT` chain'leri bulunur; `nat` gibi diğer tablolar, kernel yapılandırmasına ve yüklenen modüllere bağlı olarak kullanılabilir.<sup>[[1]](#references)</sup>

- **Input Chain**: Gelen bağlantıların davranışını yönetmek için kullanılır.
- **Forward Chain**: Yerel sistem için hedeflenmemiş gelen bağlantıları işlemek için kullanılır. Bu, alınan verilerin başka bir hedefe yönlendirilmesi gereken router olarak çalışan cihazlar için tipiktir. Bu chain, öncelikle sistem routing, NATing veya benzer etkinliklerde yer aldığında önemlidir.
- **Output Chain**: Giden bağlantıların düzenlenmesine ayrılmıştır.

Bu chain'ler, network trafiğinin düzenli şekilde işlenmesini sağlayarak verilerin bir sisteme girişini, sistem içinden geçişini ve sistemden çıkışını yöneten ayrıntılı kuralların belirlenmesine olanak tanır.

String-match örnekleri standart `string` match'i kullanır; `--icase` sağlanmadığı sürece eşleştirme büyük/küçük harfe duyarlıdır ve `--algo`, BM veya KMP arama stratejisini seçer.<sup>[[2]](#references)</sup>
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

Aşağıdaki package komutları dağıtıma ve sürüme özeldir; resmi kurulum kılavuzu Ubuntu PPA, Debian backports, RPM paketleri ve systemd service management işlemlerini belgeler.<sup>[[3]](#references)</sup>
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
`suricata-update` dizisi, kural kaynaklarını alma, listeleme, etkinleştirme ve yükleme için Suricata'nın belgelenmiş iş akışını izler.<sup>[[4]](#references)</sup> Yukarıdaki `suricatasc` komutu, belgelenmiş, engellemesiz bir Unix-socket kural yeniden yükleme yöntemidir.<sup>[[8]](#references)</sup> NFQUEUE kuralları yerel giriş/çıkış trafiğini Suricata'ya gönderirken `-q 0`, inline işleme için 0 numaralı kuyruğu seçer.<sup>[[7]](#references)</sup>

### Kural Tanımları

Bir Suricata kuralı/imzası üç bölümden oluşur.<sup>[[5]](#references)</sup>

- **Eylem**, imza eşleştiğinde ne olacağını belirtir.
- **Üst bilgi**, protokolü, IP adreslerini, portları ve yönü seçer.
- **Kural seçenekleri**, eşleşmeye özgü ayrıntıları tanımlar.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Geçerli eylemler şunlardır**

- alert - bir uyarı oluşturur
- pass - paket üzerinde daha fazla inceleme yapılmasını durdurur
- **drop** - paketi düşürür ve uyarı oluşturur
- **reject** - eşleşen paketin göndericisine RST/ICMP unreachable hatası gönderir.
- rejectsrc - yalnızca _reject_ ile aynıdır
- rejectdst - eşleşen paketin alıcısına RST/ICMP hata paketi gönderir.
- rejectboth - iletişimin her iki tarafına da RST/ICMP hata paketleri gönderir.

#### **Protokoller**

- tcp (tcp-traffic için)
- udp
- icmp
- ip (ip, ‘all’ veya ‘any’ anlamına gelir)
- _layer7 protocols_: http, ftp, tls, smb, dns, ssh ve diğerleri.<sup>[[5]](#references)</sup>

#### Kaynak ve Hedef Adresleri

Suricata IP aralıklarını, olumsuzlamayı ve gruplandırılmış adres listelerini destekler.<sup>[[5]](#references)</sup>

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | 1.1.1.1 dışındaki tüm IP adresleri             |
| !\[1.1.1.1, 1.1.1.2]          | 1.1.1.1 ve 1.1.1.2 dışındaki tüm IP adresleri |
| $HOME_NET                     | yaml içindeki HOME_NET ayarınız         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET ve HOME_NET olmayan            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.5 hariç 10.0.0.0/24          |

#### Kaynak ve Hedef Portları

Suricata port aralıklarını, olumsuzlamayı ve port listelerini destekler.<sup>[[5]](#references)</sup>

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | herhangi bir adres                            |
| \[80, 81, 82]   | 80, 81 ve 82 portları                     |
| \[80: 82]       | 80 ile 82 arasındaki aralık                  |
| \[1024: ]       | 1024'ten en yüksek port numarasına kadar |
| !80             | 80 dışındaki tüm portlar                      |
| \[80:100,!99]   | 80 ile 100 arasındaki aralık, ancak 99 hariç |
| \[1:80,!\[2,4]] | 1-80 arasındaki aralık; 2 ve 4 portları hariç  |

#### Yön

Suricata kuralları, değerlendirilen iletişim yönünü belirtebilir.<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### Anahtar Kelimeler

Aşağıdaki örneklerde Suricata'nın metadata, IP, ICMP, payload ve application-layer seçenekleri dahil olmak üzere rule keywords kullanılır; resmi rule documentation bu aileleri ve söz dizimlerini kataloglar.<sup>[[6]](#references)[[9]](#references)</sup>
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

- [1] [iptables(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Installation — Suricata 7.0.14 documentation](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Rule Management with Suricata-Update — Suricata 8.0.1 documentation](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Rules Format — Suricata 8.0.3 documentation](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Payload Keywords — Suricata 8.0.3 documentation](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Setting up IPS/inline for Linux — Suricata 7.0.15 documentation](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Rule Reloads — Suricata 7.0.14 documentation](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Suricata Rules — Suricata 8.0.3 documentation](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
