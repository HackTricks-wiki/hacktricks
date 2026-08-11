# Pcap Inspection

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> **PCAP** and **PCAPNG** are distinct capture formats; **PCAPNG is a flexible, extensible successor to PCAP**, but support varies across tools. If a tool cannot read PCAPNG, convert it to PCAP with Wireshark or another compatible tool.<sup>[[1]](#references)[[18]](#references)</sup>

## Online tools for pcaps

- If the header of your pcap is **broken** you should try to **fix** it using: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php).<sup>[[2]](#references)</sup>
- Extract **information** and search for **malware** inside a pcap in [**PacketTotal**](https://packettotal.com).<sup>[[19]](#references)</sup>
- Search for **malicious activity** using [**www.virustotal.com**](https://www.virustotal.com) and [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com).<sup>[[3]](#references)[[4]](#references)</sup>
- **Full pcap analysis from the browser in** [**https://apackets.com/**](https://apackets.com/).<sup>[[5]](#references)</sup>

## Extract Information

The following tools are useful to extract statistics, files, etc.

### Wireshark

> [!TIP]
> **If you are going to analyze a PCAP you basically must to know how to use Wireshark**

You can find some Wireshark tricks in:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Pcap analysis from the browser.<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico) is a Unix-like network-forensics tool that decodes PCAP files and can extract email over POP/IMAP/SMTP, HTTP contents, SIP VoIP calls, FTP data, and TFTP data.<sup>[[6]](#references)</sup>

**Install**

```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```

**Run**

```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```

Access to _**127.0.0.1:9876**_ with credentials _**xplico:xplico**_

Then create a **new case**, create a **new session** inside the case and **upload the pcap** file.

### NetworkMiner

Like Xplico, [**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) parses PCAP traffic to extract artifacts such as files, images, email, and passwords, and it aggregates host information; its free edition is primarily for Windows.<sup>[[7]](#references)</sup>

### NetWitness Investigator

You can download [**NetWitness Investigator from here**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(It works in Windows)**.\
The vendor describes the freeware as an interactive network-session analysis tool for malicious-activity triage and currently presents access through a contact form.<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

BruteShark's documented modules can parse credentials from HTTP, FTP, Telnet, IMAP, and SMTP, export Kerberos, NTLM, CRAM-MD5, and HTTP-Digest authentication hashes for Hashcat, map network nodes and users, extract DNS queries, rebuild TCP/UDP sessions, and carve files.<sup>[[9]](#references)</sup>

### Capinfos

Wireshark's `capinfos` prints a long report for a capture file by default.<sup>[[10]](#references)</sup>

```
capinfos capture.pcap
```

### Ngrep

`ngrep` searches packet payloads with regular expressions and accepts BPF filters; `-I` reads a pcap-compatible capture file.<sup>[[11]](#references)</sup> The example combines those features to search for an HTTP request in selected traffic.

```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```

### Carving

Using common carving techniques can be useful to extract files and information from the pcap:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturing credentials

You can use [PCredz](https://github.com/lgandx/PCredz) to parse credentials from a stored PCAP file or a live interface.<sup>[[12]](#references)</sup>

## Check Exploits/Malware

### Suricata

**Install and setup**

```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```

**Check pcap**

Suricata's `-r` option replays a PCAP in offline mode; in this example, `-k none` disables checksum checks, `-v` increases logging, and `-l` selects the log directory.<sup>[[13]](#references)</sup>

```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```

### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) processes HTTP streams from PCAP files, optionally decompresses gzip streams, scans extracted files with YARA, writes `report.txt`, and can save matching files to a directory.<sup>[[14]](#references)</sup>

### Malware Analysis

Check if you can find any fingerprint of a known malware:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) is a passive, open-source network traffic analyzer used as a Network Security Monitor (NSM) and for broader traffic analysis, including performance measurement and troubleshooting.<sup>[[15]](#references)</sup>

Zeek generates structured logs rather than PCAP files, so use log-analysis tools such as `zeek-cut` to inspect those logs.<sup>[[15]](#references)[[16]](#references)</sup>

### Connections Info

The examples below use `zeek-cut` to select named fields from TSV logs, then standard Unix tools to rank and count connections; RITA can also ingest Zeek logs for long-connection, beaconing, and DNS-tunneling analysis.<sup>[[16]](#references)[[17]](#references)</sup>

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

### DNS info

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

## Other pcap analysis tricks


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

- [1] [Wireshark User's Guide: Open Capture Files](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - online pcap / pcapng repair service](https://f00l.de/hacking/pcapfix.php)
- [3] [VirusTotal API v3 Overview](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [A-Packets PCAP Analyzer](https://apackets.com/)
- [6] [Xplico - About](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [NetWitness Investigator Freeware](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [BruteShark repository](https://github.com/odedshimon/BruteShark)
- [10] [Wireshark `capinfos` manual](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [ngrep documentation](https://ngrep.sourceforge.net/usage.html)
- [12] [PCredz repository](https://github.com/lgandx/PCredz)
- [13] [Suricata command-line options](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [YaraPcap repository](https://github.com/kevthehermit/YaraPcap)
- [15] [What Is Zeek?](https://docs.zeek.org/en/master/about/what.html)
- [16] [Zeek logs tutorial](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [RITA repository](https://github.com/activecm/rita)
- [18] [Wireshark `editcap` documentation](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [PacketTotal Upload API announcement](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)

{{#include ../../../banners/hacktricks-training.md}}
