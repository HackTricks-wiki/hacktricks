# Pcap İncelemesi

> [!TIP]
> **PCAP** ve **PCAPNG** farklı capture formatlarıdır; **PCAPNG, PCAP'in esnek ve genişletilebilir halefidir**, ancak araçlar arasındaki destek değişiklik gösterir. Bir araç PCAPNG okuyamıyorsa Wireshark veya başka bir uyumlu araçla PCAP'e dönüştürün.<sup>[[1]](#references)[[18]](#references)</sup>

## Pcap'ler için online araçlar

- Pcap'inizin header'ı **bozuksa** şu aracı kullanarak **düzeltmeyi** deneyin: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php).<sup>[[2]](#references)</sup>
- Bir pcap içinden **bilgi** çıkarın ve [**PacketTotal**](https://packettotal.com) içinde **malware** arayın.<sup>[[19]](#references)</sup>
- [**www.virustotal.com**](https://www.virustotal.com) ve [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) kullanarak **kötü amaçlı etkinlik** arayın.<sup>[[3]](#references)[[4]](#references)</sup>
- [**https://apackets.com/**](https://apackets.com/) üzerinde **tarayıcıdan tam pcap analizi** yapın.<sup>[[5]](#references)</sup>

## Bilgi Çıkarma

Aşağıdaki araçlar istatistikleri, dosyaları vb. çıkarmak için kullanışlıdır.

### Wireshark

> [!TIP]
> **Bir PCAP'i analiz edecekseniz temel olarak Wireshark'ı nasıl kullanacağınızı bilmeniz gerekir**

Bazı Wireshark ipuçlarını şurada bulabilirsiniz:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Tarayıcıdan pcap analizi.<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico), PCAP dosyalarının kodunu çözen ve POP/IMAP/SMTP üzerinden e-posta, HTTP içerikleri, SIP VoIP çağrıları, FTP verileri ve TFTP verileri çıkarabilen Unix benzeri bir network-forensics aracıdır.<sup>[[6]](#references)</sup>

**Kurulum**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Çalıştır**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
_**127.0.0.1:9876**_ adresine _**xplico:xplico**_ kimlik bilgileriyle erişin.

Ardından **new case** oluşturun, case içinde **new session** oluşturun ve **pcap** dosyasını yükleyin.

### NetworkMiner

Xplico gibi [**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner), dosyalar, görüntüler, e-postalar ve parolalar gibi artifact'leri çıkarmak için PCAP trafiğini ayrıştırır ve host bilgilerini bir araya getirir; ücretsiz sürümü öncelikle Windows içindir.<sup>[[7]](#references)</sup>

### NetWitness Investigator

[**NetWitness Investigator'ı buradan indirebilirsiniz**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Windows'ta çalışır)**.\
Vendor, freeware'i kötü amaçlı etkinliklerin triage işlemi için etkileşimli bir network-session analysis tool olarak tanımlar ve şu anda erişimi bir iletişim formu üzerinden sunar.<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

BruteShark'ın belgelenmiş modülleri HTTP, FTP, Telnet, IMAP ve SMTP üzerinden kimlik bilgilerini ayrıştırabilir; Hashcat için Kerberos, NTLM, CRAM-MD5 ve HTTP-Digest authentication hash'lerini dışa aktarabilir; network node'larını ve kullanıcıları eşleyebilir; DNS sorgularını çıkarabilir; TCP/UDP session'larını yeniden oluşturabilir ve dosyaları carve edebilir.<sup>[[9]](#references)</sup>

### Capinfos

Wireshark'ın `capinfos` aracı, varsayılan olarak bir capture file için uzun bir rapor yazdırır.<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

`ngrep`, paket payload'larını regular expressions ile arar ve BPF filtrelerini kabul eder; `-I`, pcap uyumlu bir capture file okur.<sup>[[11]](#references)</sup> Örnek, seçilen trafikte bir HTTP request aramak için bu özellikleri birleştirir.
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Yaygın carving tekniklerini kullanmak, pcap dosyasından dosyaları ve bilgileri çıkarmak için faydalı olabilir:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Kimlik bilgilerini yakalama

Kayıtlı bir PCAP dosyasından veya canlı bir arayüzden kimlik bilgilerini ayrıştırmak için [PCredz](https://github.com/lgandx/PCredz) kullanabilirsiniz.<sup>[[12]](#references)</sup>

## Exploit'leri/Kötü Amaçlı Yazılımları Kontrol Etme

### Suricata

**Kurulum ve yapılandırma**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**PCAP'ı kontrol et**

Suricata'nın `-r` seçeneği bir PCAP'ı çevrimdışı modda yeniden oynatır; bu örnekte `-k none` checksum kontrollerini devre dışı bırakır, `-v` logging seviyesini artırır ve `-l` log dizinini seçer.<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap), PCAP dosyalarındaki HTTP akışlarını işler, isteğe bağlı olarak gzip akışlarının sıkıştırmasını açar, çıkarılan dosyaları YARA ile tarar, `report.txt` dosyasını yazar ve eşleşen dosyaları bir dizine kaydedebilir.<sup>[[14]](#references)</sup>

### Malware Analizi

Bilinen bir malware'a ait herhangi bir fingerprint bulup bulamayacağınızı kontrol edin:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html), Network Security Monitor (NSM) olarak ve performans ölçümü ile sorun giderme dahil olmak üzere daha geniş trafik analizi için kullanılan pasif, open-source bir network traffic analyzer'dır.<sup>[[15]](#references)</sup>

Zeek, PCAP dosyaları yerine yapılandırılmış loglar oluşturur; bu nedenle bu logları incelemek için `zeek-cut` gibi log-analysis araçlarını kullanın.<sup>[[15]](#references)[[16]](#references)</sup>

### Bağlantı Bilgileri

Aşağıdaki örneklerde TSV loglarından adlandırılmış alanları seçmek için `zeek-cut`, ardından bağlantıları sıralamak ve saymak için standart Unix araçları kullanılır; RITA da uzun süreli bağlantı, beaconing ve DNS-tunneling analizi için Zeek loglarını alabilir.<sup>[[16]](#references)[[17]](#references)</sup>
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
### DNS bilgileri
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
## Diğer pcap analiz teknikleri


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

- [1] [Wireshark User's Guide: Capture Files'ı Açma](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - çevrimiçi pcap / pcapng onarım hizmeti](https://f00l.de/hacking/pcapfix.php)
- [3] [VirusTotal API v3 Genel Bakış](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [A-Packets PCAP Analyzer](https://apackets.com/)
- [6] [Xplico - Hakkında](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [NetWitness Investigator Freeware](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [BruteShark deposu](https://github.com/odedshimon/BruteShark)
- [10] [Wireshark `capinfos` kılavuzu](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [ngrep dokümantasyonu](https://ngrep.sourceforge.net/usage.html)
- [12] [PCredz deposu](https://github.com/lgandx/PCredz)
- [13] [Suricata komut satırı seçenekleri](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [YaraPcap deposu](https://github.com/kevthehermit/YaraPcap)
- [15] [Zeek nedir?](https://docs.zeek.org/en/master/about/what.html)
- [16] [Zeek günlükleri eğitimi](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [RITA deposu](https://github.com/activecm/rita)
- [18] [Wireshark `editcap` dokümantasyonu](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [PacketTotal Upload API duyurusu](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
