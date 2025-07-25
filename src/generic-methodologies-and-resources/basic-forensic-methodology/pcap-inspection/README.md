# Pcap Inspection

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> A note about **PCAP** vs **PCAPNG**: there are two versions of the PCAP file format; **PCAPNG is newer and not supported by all tools**. You may need to convert a file from PCAPNG to PCAP using Wireshark or another compatible tool, in order to work with it in some other tools.

## Online tools for pcaps

- If the header of your pcap is **broken** you should try to **fix** it using: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- Extract **information** and search for **malware** inside a pcap in [**PacketTotal**](https://packettotal.com)
- Search for **malicious activity** using [**www.virustotal.com**](https://www.virustotal.com) and [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)
- **Full pcap analysis from the browser in** [**https://apackets.com/**](https://apackets.com/)

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

Pcap analysis from the browser.

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(only linux)_ can **analyze** a **pcap** and extract information from it. For example, from a pcap file Xplico, extracts each email (POP, IMAP, and SMTP protocols), all HTTP contents, each VoIP call (SIP), FTP, TFTP, and so on.

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

Like Xplico it is a tool to **analyze and extract objects from pcaps**. It has a free edition that you can **download** [**here**](https://www.netresec.com/?page=NetworkMiner). It works with **Windows**.\
This tool is also useful to get **other information analysed** from the packets in order to be able to know what was happening in a **quicker** way.

### NetWitness Investigator

You can download [**NetWitness Investigator from here**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(It works in Windows)**.\
This is another useful tool that **analyses the packets** and sorts the information in a useful way to **know what is happening inside**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- Extracting and encoding usernames and passwords (HTTP, FTP, Telnet, IMAP, SMTP...)
- Extract authentication hashes and crack them using Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- Build a visual network diagram (Network nodes & users)
- Extract DNS queries
- Reconstruct all TCP & UDP Sessions
- File Carving

### Capinfos

```
capinfos capture.pcap
```

### Ngrep

If you are **looking** for **something** inside the pcap you can use **ngrep**. Here is an example using the main filters:

```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```

### Carving

Using common carving techniques can be useful to extract files and information from the pcap:

{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturing credentials

You can use tools like [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) to parse credentials from a pcap or a live interface.

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

```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```

### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) is a tool that

- Reads a PCAP File and Extracts Http Streams.
- gzip deflates any compressed streams
- Scans every file with yara
- Writes a report.txt
- Optionally saves matching files to a Dir

### Malware Analysis

Check if you can find any fingerprint of a known malware:

{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) is a passive, open-source network traffic analyzer. Many operators use Zeek as a Network Security Monitor (NSM) to support investigations of suspicious or malicious activity. Zeek also supports a wide range of traffic analysis tasks beyond the security domain, including performance measurement and troubleshooting.

Basically, logs created by `zeek` aren't **pcaps**. Therefore you will need to use **other tools** to analyse the logs where the **information** about the pcaps are.

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

​

{{#include ../../../banners/hacktricks-training.md}}



