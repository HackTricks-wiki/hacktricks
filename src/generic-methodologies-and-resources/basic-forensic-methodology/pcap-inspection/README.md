# Pcap Inspection

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> **PCAP**와 **PCAPNG**에 대한 참고 사항: **PCAP** 파일 형식에는 두 가지 버전이 있습니다. **PCAPNG는 더 최신 버전이며 모든 도구에서 지원되는 것은 아닙니다**. 일부 다른 도구에서 사용하려면 Wireshark 또는 호환되는 다른 도구를 사용해 파일을 PCAPNG에서 PCAP으로 변환해야 할 수 있습니다.

## pcap용 Online tools

- pcap의 헤더가 **손상된 경우** 다음을 사용하여 **수정**해야 합니다: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- [**PacketTotal**](https://packettotal.com)에서 pcap 내부의 **정보**를 추출하고 **malware**를 검색합니다.
- [**www.virustotal.com**](https://www.virustotal.com) 및 [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)에서 **malicious activity**를 검색합니다.
- [**https://apackets.com/**](https://apackets.com/)에서 브라우저를 통한 **전체 pcap 분석**

## 정보 추출

다음 도구는 통계, 파일 등을 추출하는 데 유용합니다.

### Wireshark

> [!TIP]
> **PCAP을 분석하려면 기본적으로 Wireshark 사용법을 알아야 합니다.**

Wireshark tricks 일부는 다음에서 확인할 수 있습니다:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

브라우저에서 수행하는 Pcap 분석입니다.

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(only linux)_는 **pcap**을 **분석**하고 그 안에서 정보를 추출할 수 있습니다. 예를 들어 Xplico는 pcap 파일에서 각 이메일(POP, IMAP 및 SMTP protocols), 모든 HTTP contents, 각 VoIP call(SIP), FTP, TFTP 등을 추출합니다.

**설치**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**실행**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
_**127.0.0.1:9876**_에 _**xplico:xplico**_ credentials로 접속합니다.

그런 다음 **new case**를 생성하고, case 내부에 **new session**을 생성한 후 **pcap** 파일을 **upload**합니다.

### NetworkMiner

Xplico와 마찬가지로 **pcap에서 objects를 analyze하고 extract**하는 tool입니다. 무료 edition을 [**여기서 download**](https://www.netresec.com/?page=NetworkMiner)할 수 있습니다. **Windows**에서 작동합니다.\
이 tool은 packets에서 **분석된 other information**을 가져와 무슨 일이 발생했는지 **더 빠른** 방식으로 파악하는 데에도 유용합니다.

### NetWitness Investigator

[**여기서 NetWitness Investigator를 download**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware)할 수 있습니다 **(Windows에서 작동)**.\
이 tool은 **packets를 analyze**하고 information을 유용한 방식으로 정렬하여 **내부에서 무슨 일이 발생하고 있는지** 파악하는 데 도움이 되는 또 다른 tool입니다.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- usernames와 passwords 추출 및 encoding (HTTP, FTP, Telnet, IMAP, SMTP...)
- authentication hashes 추출 및 Hashcat을 사용하여 crack (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- visual network diagram 생성 (Network nodes & users)
- DNS queries 추출
- 모든 TCP 및 UDP Sessions 재구성
- File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

pcap 내부에서 **무언가를** **찾고 있다면** **ngrep**을 사용할 수 있습니다. 다음은 주요 필터를 사용하는 예시입니다:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

일반적인 Carving 기법을 사용하면 pcap에서 파일과 정보를 추출하는 데 유용합니다:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### 자격 증명 캡처

[https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz)와 같은 도구를 사용하여 pcap 또는 live interface에서 자격 증명을 파싱할 수 있습니다.

## Exploits/Malware 확인

### Suricata

**설치 및 설정**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**pcap 확인**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap)은 다음 작업을 수행하는 tool입니다.

- PCAP File을 읽고 HTTP Streams를 추출합니다.
- 압축된 Streams의 gzip 압축을 해제합니다.
- 모든 파일을 yara로 스캔합니다.
- report.txt를 작성합니다.
- 선택적으로 매칭된 파일을 Dir에 저장합니다.

### Malware Analysis

알려진 malware의 fingerprint를 찾을 수 있는지 확인합니다:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html)은 passive 방식의 open-source network traffic analyzer입니다. 많은 operator는 의심스럽거나 악의적인 활동에 대한 조사를 지원하기 위해 Zeek을 Network Security Monitor (NSM)로 사용합니다. 또한 Zeek은 security domain을 넘어 performance measurement 및 troubleshooting을 포함한 다양한 traffic analysis 작업을 지원합니다.

기본적으로 `zeek`이 생성하는 logs는 **pcaps**가 아닙니다. 따라서 **pcaps에 대한 정보**가 포함된 logs를 분석하려면 **다른 tools**을 사용해야 합니다.

### Connections Info
```bash
#Get info about longest connections (add "grep udp" to see only udp traffic)
#The longest connection might be of malware (constant reverse shell?)
cat conn.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service duration | sort -nrk 7 | head -n 10

10.55.100.100   49778   65.52.108.225   443     tcp     -       86222.365445
10.55.100.107   56099   111.221.29.113  443     tcp     -       86220.126151
10.55.100.110   60168   40.77.229.82    443     tcp     -       86160.119664


#Improve the metrics by summing up the total duration time for connections that have the same destination IP and Port.
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += $5 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10

10.55.100.100   65.52.108.225   443     tcp     86222.4
10.55.100.107   111.221.29.113  443     tcp     86220.1
10.55.100.110   40.77.229.82    443     tcp     86160.1

#Get the number of connections summed up per each line
cat conn.log | zeek-cut id.orig_h id.resp_h duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2] += $3; count[$1 FS $2] += 1 } END{ for (key in arr) printf "%s%s%s%s%s\n", key, FS, count[key], FS, arr[key] }' | sort -nrk 4 | head -n 10

10.55.100.100   65.52.108.225   1       86222.4
10.55.100.107   111.221.29.113  1       86220.1
10.55.100.110   40.77.229.82    134       86160.1

#Check if any IP is connecting to 1.1.1.1
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service | grep '1.1.1.1' | sort | uniq -c

#Get number of connections per source IP, dest IP and dest Port
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += 1 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10


# RITA
#Something similar can be done with the tool rita
rita show-long-connections -H --limit 10 zeek_logs

+---------------+----------------+--------------------------+----------------+
|   SOURCE IP   | DESTINATION IP | DSTPORT:PROTOCOL:SERVICE |    DURATION    |
+---------------+----------------+--------------------------+----------------+
| 10.55.100.100 | 65.52.108.225  | 443:tcp:-                | 23h57m2.3655s  |
| 10.55.100.107 | 111.221.29.113 | 443:tcp:-                | 23h57m0.1262s  |
| 10.55.100.110 | 40.77.229.82   | 443:tcp:-                | 23h56m0.1197s  |

#Get connections info from rita
rita show-beacons zeek_logs | head -n 10
Score,Source IP,Destination IP,Connections,Avg Bytes,Intvl Range,Size Range,Top Intvl,Top Size,Top Intvl Count,Top Size Count,Intvl Skew,Size Skew,Intvl Dispersion,Size Dispersion
1,192.168.88.2,165.227.88.15,108858,197,860,182,1,89,53341,108319,0,0,0,0
1,10.55.100.111,165.227.216.194,20054,92,29,52,1,52,7774,20053,0,0,0,0
0.838,10.55.200.10,205.251.194.64,210,69,29398,4,300,70,109,205,0,0,0,0
```
### DNS 정보
```bash
#Get info about each DNS request performed
cat dns.log | zeek-cut -c id.orig_h query qtype_name answers

#Get the number of times each domain was requested and get the top 10
cat dns.log | zeek-cut query | sort | uniq | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -nr | head -n 10

#Get all the IPs
cat dns.log | zeek-cut id.orig_h query | grep 'example\.com' | cut -f 1 | sort | uniq -c

#Sort the most common DNS record request (should be A)
cat dns.log | zeek-cut qtype_name | sort | uniq -c | sort -nr

#See top DNS domain requested with rita
rita show-exploded-dns -H --limit 10 zeek_logs
```
## 기타 pcap 분석 기법


{{#ref}}
dnscat-exfiltration.md
{{#endref}}


{{#ref}}
wifi-pcap-analysis.md
{{#endref}}


{{#ref}}
usb-keystrokes.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
