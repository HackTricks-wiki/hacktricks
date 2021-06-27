# Pcap Inspection

{% hint style="info" %}
A note about **PCAP** vs **PCAPNG**: there are two versions of the PCAP file format; P**CAPNG is newer and not supported by all tools**. You may need to convert a file from PCAPNG to PCAP using Wireshark or another compatible tool, in order to work with it in some other tools.
{% endhint %}

## Online tools for pcaps

* If the header of your pcap is **broken** you should try to **fix** it using: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)\*\*\*\*
* Extract **information** and search for **malware** inside a pcap in [**PacketTotal**](https://packettotal.com/)\*\*\*\*
* Search for **malicious activity** using [**www.virustotal.com**](https://www.virustotal.com/) and [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com/)\*\*\*\*

## Extract Information

The following tools are useful to extract statistic, files...

### Wireshark

{% hint style="info" %}
**If you are going to analyze a PCAP you basically must to know how to use Wireshark**
{% endhint %}

You can find some Wireshark trick in:

{% page-ref page="wireshark-tricks.md" %}

### Xplico Framework

Xplico can **analyze** a **pcap** and extract information from it. For example, from a pcap file Xplico extracts each email \(POP, IMAP, and SMTP protocols\), all HTTP contents, each VoIP call \(SIP\), FTP, TFTP, and so on.

#### Install

```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```

#### Run

```text
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```

Access to _**127.0.0.1:9876**_ with credentials _**xplico:xplico**_

Then create a **new case**, create a **new session** inside the case and **upload the pcap** file.

### NetworkMiner

Like Xplico it is a tool to analyze and extract objects from pcaps. It has a free edition that you can download [here](https://www.netresec.com/?page=NetworkMiner).

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Extracting and encoding usernames and passwords \(HTTP, FTP, Telnet, IMAP, SMTP...\)
* Extract authentication hashes and crack them using Hashcat \(Kerberos, NTLM, CRAM-MD5, HTTP-Digest...\)
* Build visual network diagram \(Network nodes & users\)
* Extract DNS queries
* Reconstruct all TCP & UDP Sessions
* File Carving

### Capinfos

```text
capinfos capture.pcap
```

### Ngrep

If you are **looking** for **something** inside the pcap you can use **ngrep**. And example using the main filters:

```text
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```

### Carving

Using common carving techniques can be useful to extract files and information from the pcap:

{% page-ref page="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}

### Capturing credentials

You can us tools like [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) to parse credentials from a pcap or a live interface.

## Check Exploits/Malware

### Suricata

#### Install and setup

```text
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```

#### Check pcap

```text
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```

### YaraPcap

\*\*\*\*[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) is a tool that 

* Reads a PCAP File and Extracts Http Streams.
* gzip deflates any compressed streams
* Scans every file with yara
* writes a report.txt
* optionally saves matching files to a Dir

### Malware Analysis

Check if you can find any fingerprint of a known malware:

{% page-ref page="../malware-analysis.md" %}

## Other pcap analysis tricks

{% page-ref page="dnscat-exfiltration.md" %}

{% page-ref page="usb-keyboard-pcap-analysis.md" %}

{% page-ref page="wifi-pcap-analysis.md" %}

