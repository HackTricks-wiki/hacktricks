# Suricata & Iptables cheatsheet

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Iptables

### Chains

In iptables, lists of rules known as chains are processed sequentially. Among these, three primary chains are universally present, with additional ones like NAT being potentially supported depending on the system's capabilities.

- **Input Chain**: Utilized for managing the behavior of incoming connections.
- **Forward Chain**: Employed for handling incoming connections that are not destined for the local system. This is typical for devices acting as routers, where the data received is meant to be forwarded to another destination. This chain is relevant primarily when the system is involved in routing, NATing, or similar activities.
- **Output Chain**: Dedicated to the regulation of outgoing connections.

These chains ensure the orderly processing of network traffic, allowing for the specification of detailed rules governing the flow of data into, through, and out of a system.

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

### Rules Definitions

[From the docs:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) A rule/signature consists of the following:

* The **action**, determines what happens when the signature matches.
* The **header**, defines the protocol, IP addresses, ports and direction of the rule.
* The **rule options**, define the specifics of the rule.

```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```

#### **Valid actions are**

* alert - generate an alert
* pass - stop further inspection of the packet
* **drop** - drop packet and generate alert
* **reject** - send RST/ICMP unreachable error to the sender of the matching packet.
* rejectsrc - same as just _reject_
* rejectdst - send RST/ICMP error packet to the receiver of the matching packet.
* rejectboth - send RST/ICMP error packets to both sides of the conversation.

#### **Protocols**

* tcp (for tcp-traffic)
* udp
* icmp
* ip (ip stands for ‘all’ or ‘any’)
* _layer7 protocols_: http, ftp, tls, smb, dns, ssh... (more in the [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Source and Destination Addresses

It supports IP ranges, negations and a list of addresses:

| Example                        | Meaning                                  |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | Every IP address but 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]           | Every IP address but 1.1.1.1 and 1.1.1.2 |
| $HOME\_NET                     | Your setting of HOME\_NET in yaml        |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET and not HOME\_NET          |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24 except for 10.0.0.5          |

#### Source and Destination Ports

It supports port ranges, negations and lists of ports

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

It's possible to indicate the direction of the communication rule being applied:

```
source -> destination
source <> destination  (both directions)
```

#### Keywords

There are **hundreds of options** available in Suricata to search for the **specific packet** you are looking for, here it will be mentioned if something interesting is found. Check the [**documentation** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)for more!

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

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

