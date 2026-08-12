# Suricata & Iptables cheatsheet

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chains

In iptables, each chain is a sequential list of packet-matching rules. The default `filter` table has the built-in `INPUT`, `FORWARD`, and `OUTPUT` chains; other tables, such as `nat`, may be available depending on kernel configuration and loaded modules.<sup>[[1]](#references)</sup>

- **Input Chain**: Utilized for managing the behavior of incoming connections.
- **Forward Chain**: Employed for handling incoming connections that are not destined for the local system. This is typical for devices acting as routers, where the data received is meant to be forwarded to another destination. This chain is relevant primarily when the system is involved in routing, NATing, or similar activities.
- **Output Chain**: Dedicated to the regulation of outgoing connections.

These chains ensure the orderly processing of network traffic, allowing for the specification of detailed rules governing the flow of data into, through, and out of a system.

The string-match examples use the standard `string` match; matching is case-sensitive unless `--icase` is supplied, and `--algo` selects the BM or KMP search strategy.<sup>[[2]](#references)</sup>

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

### Install & Config

Package commands below are distribution- and release-specific; the official installation guide documents the Ubuntu PPA, Debian backports, RPM packages, and systemd service management.<sup>[[3]](#references)</sup>

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

The `suricata-update` sequence follows Suricata's documented workflow for fetching, listing, enabling, and loading rule sources.<sup>[[4]](#references)</sup> The `suricatasc` command above is a documented non-blocking Unix-socket rule-reload method.<sup>[[8]](#references)</sup> The NFQUEUE rules send local input/output traffic to Suricata, while `-q 0` selects queue 0 for inline processing.<sup>[[7]](#references)</sup>

### Rules Definitions

A Suricata rule/signature has three parts.<sup>[[5]](#references)</sup>

- The **action** specifies what happens when the signature matches.
- The **header** selects the protocol, IP addresses, ports, and direction.
- The **rule options** define the match-specific details.

```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```

#### **Valid actions are**

- alert - generate an alert
- pass - stop further inspection of the packet
- **drop** - drop packet and generate alert
- **reject** - send RST/ICMP unreachable error to the sender of the matching packet.
- rejectsrc - same as just _reject_
- rejectdst - send RST/ICMP error packet to the receiver of the matching packet.
- rejectboth - send RST/ICMP error packets to both sides of the conversation.

#### **Protocols**

- tcp (for tcp-traffic)
- udp
- icmp
- ip (ip stands for ‘all’ or ‘any’)
- _layer7 protocols_: http, ftp, tls, smb, dns, ssh, and others.<sup>[[5]](#references)</sup>

#### Source and Destination Addresses

Suricata supports IP ranges, negation, and grouped address lists.<sup>[[5]](#references)</sup>

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | Every IP address but 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]          | Every IP address but 1.1.1.1 and 1.1.1.2 |
| $HOME_NET                     | Your setting of HOME_NET in yaml         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET and not HOME_NET            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 except for 10.0.0.5          |

#### Source and Destination Ports

Suricata supports port ranges, negation, and lists of ports.<sup>[[5]](#references)</sup>

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | any address                            |
| \[80, 81, 82]   | port 80, 81 and 82                     |
| \[80: 82]       | Range from 80 till 82                  |
| \[1024: ]       | From 1024 till the highest port-number |
| !80             | Every port but 80                      |
| \[80:100,!99]   | Range from 80 till 100 but 99 excluded |
| \[1:80,!\[2,4]] | Range from 1-80, except ports 2 and 4  |

#### Direction

Suricata rules can specify the communication direction being evaluated.<sup>[[5]](#references)</sup>

```
source -> destination
source <> destination  (both directions)
```

#### Keywords

The examples below use Suricata's rule keywords, including metadata, IP, ICMP, payload, and application-layer options; the official rule documentation catalogs these families and their syntax.<sup>[[6]](#references)[[9]](#references)</sup>

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

- [1] [iptables(8) — Linux manual page](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — Linux manual page](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Installation — Suricata 7.0.14 documentation](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Rule Management with Suricata-Update — Suricata 8.0.1 documentation](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Rules Format — Suricata 8.0.3 documentation](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Payload Keywords — Suricata 8.0.3 documentation](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Setting up IPS/inline for Linux — Suricata 7.0.15 documentation](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Rule Reloads — Suricata 7.0.14 documentation](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Suricata Rules — Suricata 8.0.3 documentation](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)

{{#include ../../../banners/hacktricks-training.md}}
