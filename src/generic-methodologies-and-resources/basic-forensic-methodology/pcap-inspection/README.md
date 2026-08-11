# Pcap 검사

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> **PCAP**과 **PCAPNG**는 서로 다른 capture format입니다. **PCAPNG는 PCAP을 계승한 유연하고 확장 가능한 format**이지만, tool마다 지원 여부가 다릅니다. tool이 PCAPNG를 읽지 못하면 Wireshark 또는 호환되는 다른 tool을 사용해 PCAP으로 변환하세요.<sup>[[1]](#references)[[18]](#references)</sup>

## pcap용 온라인 도구

- pcap의 header가 **손상된** 경우 다음을 사용해 **수정**해 보세요: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php).<sup>[[2]](#references)</sup>
- [**PacketTotal**](https://packettotal.com)에서 pcap 내부의 **정보**를 추출하고 **malware**를 검색하세요.<sup>[[19]](#references)</sup>
- [**www.virustotal.com**](https://www.virustotal.com) 및 [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)을 사용해 **악성 활동**을 검색하세요.<sup>[[3]](#references)[[4]](#references)</sup>
- 브라우저에서 수행하는 **전체 pcap 분석**: [**https://apackets.com/**](https://apackets.com/).<sup>[[5]](#references)</sup>

## 정보 추출

다음 tool은 통계, 파일 등을 추출하는 데 유용합니다.

### Wireshark

> [!TIP]
> **PCAP을 분석하려면 기본적으로 Wireshark 사용법을 알아야 합니다**

다음에서 Wireshark tricks를 확인할 수 있습니다:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

브라우저에서 수행하는 pcap 분석입니다.<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico)는 PCAP 파일을 decode하고 POP/IMAP/SMTP를 통한 email, HTTP contents, SIP VoIP calls, FTP data 및 TFTP data를 추출할 수 있는 Unix-like network-forensics tool입니다.<sup>[[6]](#references)</sup>

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
_**127.0.0.1:9876**_에 _**xplico:xplico**_ 자격 증명으로 접속합니다.

그런 다음 **새 case**를 생성하고, case 내부에 **새 session**을 생성한 후 **pcap** 파일을 업로드합니다.

### NetworkMiner

Xplico와 마찬가지로 [**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner)는 PCAP 트래픽을 분석하여 파일, 이미지, email, password 등의 artifact를 추출하고 host 정보를 집계합니다. 무료 버전은 주로 Windows용입니다.<sup>[[7]](#references)</sup>

### NetWitness Investigator

[**NetWitness Investigator는 여기에서 다운로드할 수 있습니다**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Windows에서 작동합니다)**.\
공급업체는 이 freeware를 악성 활동 triage를 위한 대화형 network-session analysis tool로 설명하며, 현재는 contact form을 통해 액세스를 제공합니다.<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

BruteShark의 문서화된 modules는 HTTP, FTP, Telnet, IMAP, SMTP에서 credentials를 파싱하고, Hashcat용 Kerberos, NTLM, CRAM-MD5, HTTP-Digest authentication hashes를 export하며, network nodes와 users를 매핑하고, DNS queries를 추출하며, TCP/UDP sessions를 재구성하고, files를 carve할 수 있습니다.<sup>[[9]](#references)</sup>

### Capinfos

Wireshark의 `capinfos`는 기본적으로 capture file에 대한 긴 report를 출력합니다.<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

`ngrep`은 정규 표현식으로 packet payload를 검색하고 BPF filters를 허용하며, `-I`는 pcap 호환 캡처 파일을 읽습니다.<sup>[[11]](#references)</sup> 이 예제는 이러한 기능을 결합하여 선택한 traffic에서 HTTP 요청을 검색합니다.
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### 카빙

일반적인 카빙 기법을 사용하면 pcap에서 파일과 정보를 추출하는 데 유용합니다:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### 자격 증명 캡처

[PCredz](https://github.com/lgandx/PCredz)를 사용하여 저장된 PCAP 파일 또는 라이브 인터페이스에서 자격 증명을 파싱할 수 있습니다.<sup>[[12]](#references)</sup>

## 익스플로잇/멀웨어 확인

### Suricata

**설치 및 설정**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**pcap 확인**

Suricata의 `-r` 옵션은 오프라인 모드에서 PCAP을 재생합니다. 이 예제에서 `-k none`은 checksum 검사를 비활성화하고, `-v`는 logging을 증가시키며, `-l`은 log 디렉터리를 지정합니다.<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap)는 PCAP 파일의 HTTP 스트림을 처리하고, 선택적으로 gzip 스트림의 압축을 해제하며, 추출된 파일을 YARA로 스캔하고, `report.txt`를 작성하며, 일치하는 파일을 디렉터리에 저장할 수 있습니다.<sup>[[14]](#references)</sup>

### Malware Analysis

알려진 malware의 fingerprint를 찾을 수 있는지 확인합니다:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html)는 Network Security Monitor (NSM) 및 성능 측정과 문제 해결을 포함한 광범위한 traffic analysis에 사용되는 passive open-source network traffic analyzer입니다.<sup>[[15]](#references)</sup>

Zeek는 PCAP 파일 대신 구조화된 로그를 생성하므로, `zeek-cut`과 같은 log-analysis 도구를 사용하여 해당 로그를 검사합니다.<sup>[[15]](#references)[[16]](#references)</sup>

### Connections Info

아래 예제에서는 `zeek-cut`을 사용하여 TSV 로그에서 지정된 field를 선택한 다음, 표준 Unix 도구를 사용하여 connection의 순위를 정하고 개수를 계산합니다. RITA를 사용하면 장시간 connection, beaconing 및 DNS-tunneling analysis를 위해 Zeek 로그를 ingest할 수도 있습니다.<sup>[[16]](#references)[[17]](#references)</sup>
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

## References

- [1] [Wireshark User's Guide: 캡처 파일 열기](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - 온라인 pcap / pcapng 복구 서비스](https://f00l.de/hacking/pcapfix.php)
- [3] [VirusTotal API v3 개요](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [A-Packets PCAP Analyzer](https://apackets.com/)
- [6] [Xplico - 소개](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [NetWitness Investigator Freeware](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [BruteShark repository](https://github.com/odedshimon/BruteShark)
- [10] [Wireshark `capinfos` 매뉴얼](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [ngrep documentation](https://ngrep.sourceforge.net/usage.html)
- [12] [PCredz repository](https://github.com/lgandx/PCredz)
- [13] [Suricata command-line options](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [YaraPcap repository](https://github.com/kevthehermit/YaraPcap)
- [15] [Zeek이란 무엇인가?](https://docs.zeek.org/en/master/about/what.html)
- [16] [Zeek logs tutorial](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [RITA repository](https://github.com/activecm/rita)
- [18] [Wireshark `editcap` documentation](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [PacketTotal Upload API announcement](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
