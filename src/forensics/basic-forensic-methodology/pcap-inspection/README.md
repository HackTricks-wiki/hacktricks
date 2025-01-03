# Pcap Inspection

{{#include ../../../banners/hacktricks-training.md}}

> [!NOTE]
> **PCAP**와 **PCAPNG**에 대한 주의: PCAP 파일 형식에는 두 가지 버전이 있습니다; **PCAPNG는 더 최신이며 모든 도구에서 지원되지 않습니다**. 다른 도구에서 작업하기 위해 Wireshark 또는 다른 호환 도구를 사용하여 PCAPNG에서 PCAP로 파일을 변환해야 할 수도 있습니다.

## pcaps를 위한 온라인 도구

- pcap의 헤더가 **손상된** 경우: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)를 사용하여 **수정**해 보십시오.
- [**PacketTotal**](https://packettotal.com)에서 pcap 내의 **정보**를 추출하고 **악성코드**를 검색하십시오.
- [**www.virustotal.com**](https://www.virustotal.com) 및 [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)에서 **악의적인 활동**을 검색하십시오.

## 정보 추출

다음 도구는 통계, 파일 등을 추출하는 데 유용합니다.

### Wireshark

> [!NOTE]
> **PCAP을 분석하려면 기본적으로 Wireshark를 사용하는 방법을 알아야 합니다.**

다음에서 Wireshark 팁을 찾을 수 있습니다:

{{#ref}}
wireshark-tricks.md
{{#endref}}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(리눅스 전용)_는 **pcap**을 **분석**하고 그로부터 정보를 추출할 수 있습니다. 예를 들어, pcap 파일에서 Xplico는 각 이메일(POP, IMAP 및 SMTP 프로토콜), 모든 HTTP 콘텐츠, 각 VoIP 통화(SIP), FTP, TFTP 등을 추출합니다.

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
_**127.0.0.1:9876**_에 _**xplico:xplico**_ 자격 증명으로 접근합니다.

그런 다음 **새 사례**를 만들고, 사례 내에서 **새 세션**을 생성한 후 **pcap** 파일을 **업로드**합니다.

### NetworkMiner

Xplico와 마찬가지로 **pcap에서 객체를 분석하고 추출하는** 도구입니다. 무료 버전이 있으며, [**여기서 다운로드**](https://www.netresec.com/?page=NetworkMiner)할 수 있습니다. **Windows**에서 작동합니다.\
이 도구는 패킷에서 **분석된 다른 정보를 얻는 데** 유용하여 **더 빠르게** 무슨 일이 일어나고 있는지 알 수 있습니다.

### NetWitness Investigator

[**여기서 NetWitness Investigator를 다운로드**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware)할 수 있습니다 **(Windows에서 작동합니다)**.\
이것은 패킷을 **분석하고** 정보를 유용한 방식으로 정리하여 **내부에서 무슨 일이 일어나고 있는지 알 수 있는** 또 다른 유용한 도구입니다.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- 사용자 이름 및 비밀번호 추출 및 인코딩 (HTTP, FTP, Telnet, IMAP, SMTP...)
- 인증 해시 추출 및 Hashcat을 사용하여 크랙 (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- 시각적 네트워크 다이어그램 구축 (네트워크 노드 및 사용자)
- DNS 쿼리 추출
- 모든 TCP 및 UDP 세션 재구성
- 파일 조각화

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

pcap 내에서 **무언가**를 **찾고** 있다면 **ngrep**을 사용할 수 있습니다. 다음은 주요 필터를 사용하는 예입니다:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

일반적인 카빙 기술을 사용하면 pcap에서 파일과 정보를 추출하는 데 유용할 수 있습니다:

{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturing credentials

pcap 또는 라이브 인터페이스에서 자격 증명을 구문 분석하기 위해 [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz)와 같은 도구를 사용할 수 있습니다.

## Check Exploits/Malware

### Suricata

**Install and setup**
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

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap)는 다음과 같은 도구입니다.

- PCAP 파일을 읽고 Http 스트림을 추출합니다.
- gzip은 압축된 스트림을 해제합니다.
- 모든 파일을 yara로 스캔합니다.
- report.txt를 작성합니다.
- 선택적으로 일치하는 파일을 디렉토리에 저장합니다.

### Malware Analysis

알려진 악성코드의 지문을 찾을 수 있는지 확인하세요:

{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html)은 수동 오픈 소스 네트워크 트래픽 분석기입니다. 많은 운영자들이 Zeek을 네트워크 보안 모니터(NSM)로 사용하여 의심스러운 또는 악의적인 활동에 대한 조사를 지원합니다. Zeek은 보안 도메인을 넘어 성능 측정 및 문제 해결을 포함한 다양한 트래픽 분석 작업을 지원합니다.

기본적으로 `zeek`에 의해 생성된 로그는 **pcap**이 아닙니다. 따라서 **pcap**에 대한 **정보**가 있는 로그를 분석하기 위해 **다른 도구**를 사용해야 합니다.

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
## 다른 pcap 분석 팁

{{#ref}}
dnscat-exfiltration.md
{{#endref}}

{{#ref}}
wifi-pcap-analysis.md
{{#endref}}

{{#ref}}
usb-keystrokes.md
{{#endref}}

​

{{#include ../../../banners/hacktricks-training.md}}
