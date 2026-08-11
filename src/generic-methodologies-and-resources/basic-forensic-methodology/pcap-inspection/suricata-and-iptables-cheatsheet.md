# Suricata & Iptables 速查表

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### 链

在 iptables 中，每个链都是按顺序排列的数据包匹配规则列表。默认的 `filter` 表包含内置的 `INPUT`、`FORWARD` 和 `OUTPUT` 链；根据内核配置和已加载的模块，可能还会有其他表，例如 `nat`。<sup>[[1]](#references)</sup>

- **Input Chain**：用于管理传入连接的行为。
- **Forward Chain**：用于处理目标不是本地系统的传入连接。这通常适用于充当路由器的设备，因为接收到的数据需要被转发到其他目标。此链主要在系统参与路由、NAT 或类似活动时发挥作用。
- **Output Chain**：专门用于管理传出连接。

这些链确保网络流量得到有序处理，从而可以指定详细规则来控制数据流入、经过和流出系统的过程。

字符串匹配示例使用标准的 `string` match；除非提供 `--icase`，否则匹配区分大小写；`--algo` 用于选择 BM 或 KMP 搜索策略。<sup>[[2]](#references)</sup>
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

下面的包管理命令因发行版和版本而异；官方安装指南介绍了 Ubuntu PPA、Debian backports、RPM packages 以及 systemd 服务管理。<sup>[[3]](#references)</sup>
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
`suricata-update` sequence 遵循 Suricata 记录的工作流程，用于获取、列出、启用和加载规则源。<sup>[[4]](#references)</sup> 上面的 `suricatasc` 命令是一种有文档说明的非阻塞 Unix socket 规则重新加载方法。<sup>[[8]](#references)</sup> NFQUEUE 规则将本地输入/输出流量发送到 Suricata，而 `-q 0` 选择队列 0 进行 inline 处理。<sup>[[7]](#references)</sup>

### 规则定义

Suricata 规则/签名由三部分组成。<sup>[[5]](#references)</sup>

- **action** 指定签名匹配时发生的情况。
- **header** 选择协议、IP 地址、端口和方向。
- **rule options** 定义与匹配相关的具体细节。
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **有效操作包括**

- alert - 生成 alert
- pass - 停止对数据包的进一步检查
- **drop** - 丢弃数据包并生成 alert
- **reject** - 向匹配数据包的发送方发送 RST/ICMP unreachable 错误。
- rejectsrc - 与 _reject_ 相同
- rejectdst - 向匹配数据包的接收方发送 RST/ICMP 错误数据包。
- rejectboth - 向通信双方发送 RST/ICMP 错误数据包。

#### **Protocols**

- tcp（用于 tcp-traffic）
- udp
- icmp
- ip（ip 代表“all”或“any”）
- _layer7 protocols_：http、ftp、tls、smb、dns、ssh 及其他协议。<sup>[[5]](#references)</sup>

#### 源地址和目标地址

Suricata 支持 IP 范围、否定和分组地址列表。<sup>[[5]](#references)</sup>

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | 除 1.1.1.1 之外的所有 IP 地址             |
| !\[1.1.1.1, 1.1.1.2]          | 除 1.1.1.1 和 1.1.1.2 之外的所有 IP 地址 |
| $HOME_NET                     | yaml 中对 HOME_NET 的设置                |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET 而非 HOME_NET               |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24，但不包括 10.0.0.5           |

#### 源端口和目标端口

Suricata 支持端口范围、否定和端口列表。<sup>[[5]](#references)</sup>

| Example         | Meaning                                  |
| --------------- | ---------------------------------------- |
| any             | 任意地址                                 |
| \[80, 81, 82]   | 端口 80、81 和 82                        |
| \[80: 82]       | 从 80 到 82 的范围                       |
| \[1024: ]       | 从 1024 到最高端口号                     |
| !80             | 除 80 之外的所有端口                    |
| \[80:100,!99]   | 从 80 到 100 的范围，但不包括 99         |
| \[1:80,!\[2,4]] | 从 1 到 80 的范围，但不包括端口 2 和 4   |

#### 方向

Suricata 规则可以指定要评估的通信方向。<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### 关键词

下面的示例使用 Suricata 的规则关键字，包括 metadata、IP、ICMP、payload 和应用层选项；官方规则文档对这些类别及其语法进行了分类说明。<sup>[[6]](#references)[[9]](#references)</sup>
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

- [1] [iptables(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. 安装 — Suricata 7.0.14 文档](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. 使用 Suricata-Update 管理规则 — Suricata 8.0.1 文档](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. 规则格式 — Suricata 8.0.3 文档](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Payload 关键字 — Suricata 8.0.3 文档](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. 为 Linux 设置 IPS/inline — Suricata 7.0.15 文档](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. 规则重新加载 — Suricata 7.0.14 文档](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Suricata 规则 — Suricata 8.0.3 文档](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
