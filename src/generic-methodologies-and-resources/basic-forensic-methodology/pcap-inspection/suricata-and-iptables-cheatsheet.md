# Suricata & Iptables 速查表

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### 链

在 iptables 中，称为链的规则列表会按顺序进行处理。其中，三个主要链始终存在；根据系统功能，可能还支持 NAT 等其他链。

- **输入链**：用于管理传入连接的行为。
- **转发链**：用于处理并非发往本地系统的传入连接。这通常适用于充当路由器的设备，因为接收到的数据需要转发到其他目标。此链主要在系统参与路由、NAT 或类似活动时发挥作用。
- **输出链**：专用于管理传出连接。

这些链确保网络流量得到有序处理，从而能够制定详细规则，控制数据流入、经过和流出系统的过程。
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

### 安装与配置
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
### 规则定义

[From the docs:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) 一条规则/签名由以下部分组成：

- **操作**，决定签名匹配时会发生什么。
- **标头**，定义规则的协议、IP 地址、端口和方向。
- **规则选项**，定义规则的具体内容。
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **有效的 actions 包括**

- alert - 生成 alert
- pass - 停止对数据包的进一步检查
- **drop** - 丢弃数据包并生成 alert
- **reject** - 向匹配数据包的发送方发送 RST/ICMP unreachable error。
- rejectsrc - 与 _reject_ 相同
- rejectdst - 向匹配数据包的接收方发送 RST/ICMP error 数据包。
- rejectboth - 向通信双方发送 RST/ICMP error 数据包。

#### **Protocols**

- tcp (用于 tcp-traffic)
- udp
- icmp
- ip (ip 表示“全部”或“任意”)
- _layer7 protocols_: http, ftp, tls, smb, dns, ssh...（更多内容请参阅[**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html)）

#### 源地址和目标地址

它支持 IP 范围、否定和地址列表：

| 示例                          | 含义                                  |
| ----------------------------- | ------------------------------------- |
| ! 1.1.1.1                     | 除 1.1.1.1 外的所有 IP 地址           |
| !\[1.1.1.1, 1.1.1.2]          | 除 1.1.1.1 和 1.1.1.2 外的所有 IP 地址 |
| $HOME_NET                     | yaml 中对 HOME_NET 的设置             |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET 而非 HOME_NET             |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24，但不包括 10.0.0.5        |

#### 源端口和目标端口

它支持端口范围、否定和端口列表：

| 示例            | 含义                              |
| --------------- | --------------------------------- |
| any             | 任意地址                          |
| \[80, 81, 82]   | 端口 80、81 和 82                 |
| \[80: 82]       | 从 80 到 82 的范围                |
| \[1024: ]       | 从 1024 到最高端口号               |
| !80             | 除 80 外的所有端口                |
| \[80:100,!99]   | 从 80 到 100 的范围，但不包括 99   |
| \[1:80,!\[2,4]] | 从 1 到 80 的范围，但不包括端口 2 和 4 |

#### 方向

可以指示所应用通信规则的方向：
```
source -> destination
source <> destination  (both directions)
```
#### 关键词

Suricata 中有**数百种选项**可用于搜索你正在寻找的**特定数据包**，如果发现有趣的内容，这里会对其进行说明。请查看[**文档** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)了解更多信息！
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
