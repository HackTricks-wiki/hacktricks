# Karatasi ya kumbukumbu ya Suricata & Iptables

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Minyororo

Katika iptables, kila mnyororo ni orodha ya mfululizo ya sheria za kulinganisha pakiti. Jedwali chaguo-msingi la `filter` lina minyororo iliyojengwa ndani ya `INPUT`, `FORWARD`, na `OUTPUT`; jedwali nyingine, kama vile `nat`, zinaweza kupatikana kulingana na usanidi wa kernel na modules zilizopakiwa.<sup>[[1]](#references)</sup>

- **Mnyororo wa Input**: Hutumika kudhibiti tabia ya connections zinazoingia.
- **Mnyororo wa Forward**: Hutumika kushughulikia connections zinazoingia ambazo hazikulengwa kwa mfumo wa ndani. Hii ni kawaida kwa vifaa vinavyofanya kazi kama routers, ambapo data iliyopokelewa inakusudiwa kutumwa kwenye destination nyingine. Mnyororo huu unahusika hasa wakati mfumo unashiriki katika routing, NATing, au shughuli zinazofanana.
- **Mnyororo wa Output**: Umejitolea kudhibiti connections zinazotoka.

Minyororo hii huhakikisha uchakataji wenye mpangilio wa traffic ya mtandao, na kuruhusu kubainishwa kwa sheria za kina zinazosimamia mtiririko wa data kuingia, kupitia, na kutoka kwenye mfumo.

Mifano ya string-match hutumia `string` match ya kawaida; matching huzingatia ukubwa wa herufi isipokuwa `--icase` itolewe, na `--algo` huchagua mkakati wa utafutaji wa BM au KMP.<sup>[[2]](#references)</sup>
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

### Usakinishaji na Usanidi

Amri za vifurushi hapa chini hutegemea distribution na release; mwongozo rasmi wa usakinishaji unaeleza Ubuntu PPA, Debian backports, vifurushi vya RPM, na usimamizi wa huduma ya systemd.<sup>[[3]](#references)</sup>
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
Mtiririko wa `suricata-update` hufuata workflow iliyowekwa kwenye nyaraka za Suricata ya kuchukua, kuorodhesha, kuwezesha na kupakia vyanzo vya rules.<sup>[[4]](#references)</sup> Amri ya `suricatasc` hapo juu ni njia iliyo kwenye nyaraka ya kupakia upya rules kupitia Unix socket bila kuzuia shughuli nyingine.<sup>[[8]](#references)</sup> Rules za NFQUEUE hutuma traffic ya local input/output kwa Suricata, huku `-q 0` ikichagua queue 0 kwa inline processing.<sup>[[7]](#references)</sup>

### Ufafanuzi wa Rules

Rule/signature ya Suricata ina sehemu tatu.<sup>[[5]](#references)</sup>

- **action** hubainisha kinachotokea signature inapolingana.
- **header** huchagua protocol, IP addresses, ports na direction.
- **rule options** hufafanua maelezo mahususi ya ulinganishaji.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Vitendo halali ni**

- alert - generate an alert
- pass - stop further inspection of the packet
- **drop** - drop packet and generate alert
- **reject** - send RST/ICMP unreachable error to the sender of the matching packet.
- rejectsrc - same as just _reject_
- rejectdst - send RST/ICMP error packet to the receiver of the matching packet.
- rejectboth - send RST/ICMP error packets to both sides of the conversation.

#### **Itifaki**

- tcp (for tcp-traffic)
- udp
- icmp
- ip (ip stands for ‘all’ or ‘any’)
- _layer7 protocols_: http, ftp, tls, smb, dns, ssh, and others.<sup>[[5]](#references)</sup>

#### Anwani za Chanzo na Lengwa

Suricata inaauni safu za IP, ukanushaji, na orodha za anwani zilizowekwa katika vikundi.<sup>[[5]](#references)</sup>

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | Kila anwani ya IP isipokuwa 1.1.1.1     |
| !\[1.1.1.1, 1.1.1.2]          | Kila anwani ya IP isipokuwa 1.1.1.1 na 1.1.1.2 |
| $HOME_NET                     | Mpangilio wako wa HOME_NET katika yaml   |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET na si HOME_NET              |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 isipokuwa 10.0.0.5          |

#### Porti za Chanzo na Lengwa

Suricata inaauni safu za porti, ukanushaji, na orodha za porti.<sup>[[5]](#references)</sup>

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | anwani yoyote                          |
| \[80, 81, 82]   | porti 80, 81 na 82                     |
| \[80: 82]       | Safu kuanzia 80 hadi 82                |
| \[1024: ]       | Kuanzia 1024 hadi nambari ya juu zaidi ya porti |
| !80             | Kila porti isipokuwa 80                |
| \[80:100,!99]   | Safu kuanzia 80 hadi 100 isipokuwa 99  |
| \[1:80,!\[2,4]] | Safu kuanzia 1 hadi 80, isipokuwa porti 2 na 4 |

#### Mwelekeo

Sheria za Suricata zinaweza kubainisha mwelekeo wa mawasiliano unaotathminiwa.<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### Maneno muhimu

Mifano iliyo hapa chini inatumia keywords za rules za Suricata, ikijumuisha metadata, IP, ICMP, payload, na chaguo za application layer; nyaraka rasmi za rules zinaorodhesha familia hizi na syntax yake.<sup>[[6]](#references)[[9]](#references)</sup>
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

- [1] [iptables(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Usakinishaji — nyaraka za Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Usimamizi wa Rules kwa kutumia Suricata-Update — nyaraka za Suricata 8.0.1](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Muundo wa Rules — nyaraka za Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Payload Keywords — nyaraka za Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Kuweka IPS/inline kwa Linux — nyaraka za Suricata 7.0.15](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Kupakia upya Rules — nyaraka za Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Suricata Rules — nyaraka za Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
