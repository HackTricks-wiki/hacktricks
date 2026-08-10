# Ispezione dei Pcap

> [!TIP]
> **PCAP** e **PCAPNG** sono formati di cattura distinti; **PCAPNG è un successore flessibile ed estensibile di PCAP**, ma il supporto varia a seconda degli strumenti. Se uno strumento non riesce a leggere PCAPNG, convertilo in PCAP con Wireshark o un altro strumento compatibile.<sup>[[1]](#references)[[18]](#references)</sup>

## Strumenti online per i pcap

- Se l'header del tuo pcap è **danneggiato**, dovresti provare a **ripararlo** usando: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php).<sup>[[2]](#references)</sup>
- Estrai **informazioni** e cerca **malware** all'interno di un pcap su [**PacketTotal**](https://packettotal.com).<sup>[[19]](#references)</sup>
- Cerca **attività malevole** usando [**www.virustotal.com**](https://www.virustotal.com) e [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com).<sup>[[3]](#references)[[4]](#references)</sup>
- **Analisi completa del pcap dal browser su** [**https://apackets.com/**](https://apackets.com/).<sup>[[5]](#references)</sup>

## Estrazione delle informazioni

I seguenti strumenti sono utili per estrarre statistiche, file, ecc.

### Wireshark

> [!TIP]
> **Se intendi analizzare un PCAP, devi assolutamente sapere come usare Wireshark**

Puoi trovare alcuni trucchi di Wireshark in:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Analisi dei pcap dal browser.<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico) è uno strumento di network forensics per sistemi Unix-like che decodifica i file PCAP ed è in grado di estrarre email tramite POP/IMAP/SMTP, contenuti HTTP, chiamate SIP VoIP, dati FTP e dati TFTP.<sup>[[6]](#references)</sup>

**Installazione**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Esegui**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Accesso a _**127.0.0.1:9876**_ con le credenziali _**xplico:xplico**_

Quindi crea un **nuovo caso**, crea una **nuova sessione** all'interno del caso e **carica il** file **pcap**.

### NetworkMiner

Come Xplico, [**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) analizza il traffico PCAP per estrarre artefatti come file, immagini, email e password e aggrega le informazioni sugli host; la sua edizione gratuita è principalmente per Windows.<sup>[[7]](#references)</sup>

### NetWitness Investigator

Puoi scaricare [**NetWitness Investigator da qui**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(funziona su Windows)**.\
Il produttore descrive il freeware come uno strumento interattivo di analisi delle sessioni di rete per il triage delle attività malevole e attualmente presenta l'accesso tramite un modulo di contatto.<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

I moduli documentati di BruteShark possono analizzare le credenziali provenienti da HTTP, FTP, Telnet, IMAP e SMTP, esportare gli hash di autenticazione Kerberos, NTLM, CRAM-MD5 e HTTP-Digest per Hashcat, mappare nodi e utenti della rete, estrarre query DNS, ricostruire sessioni TCP/UDP ed eseguire il file carving.<sup>[[9]](#references)</sup>

### Capinfos

Il `capinfos` di Wireshark stampa per impostazione predefinita un report dettagliato per un file di cattura.<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

`ngrep` cerca nei payload dei pacchetti usando espressioni regolari e accetta filtri BPF; `-I` legge un file di cattura compatibile con pcap.<sup>[[11]](#references)</sup> L'esempio combina queste funzionalità per cercare una richiesta HTTP nel traffico selezionato.
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

L'utilizzo di tecniche comuni di carving può essere utile per estrarre file e informazioni dal pcap:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Acquisizione delle credenziali

Puoi utilizzare [PCredz](https://github.com/lgandx/PCredz) per analizzare le credenziali da un file PCAP salvato o da un'interfaccia live.<sup>[[12]](#references)</sup>

## Verifica di Exploits/Malware

### Suricata

**Installazione e configurazione**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Controllare pcap**

L'opzione `-r` di Suricata riproduce un PCAP in modalità offline; in questo esempio, `-k none` disabilita i controlli del checksum, `-v` aumenta il livello di logging e `-l` seleziona la directory dei log.<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) elabora gli stream HTTP dai file PCAP, decomprime facoltativamente gli stream gzip, analizza i file estratti con YARA, scrive `report.txt` e può salvare i file corrispondenti in una directory.<sup>[[14]](#references)</sup>

### Analisi del malware

Verifica se riesci a trovare qualche fingerprint di un malware noto:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) è un analizzatore passivo e open-source del traffico di rete, utilizzato come Network Security Monitor (NSM) e per un'analisi più ampia del traffico, inclusi la misurazione delle prestazioni e il troubleshooting.<sup>[[15]](#references)</sup>

Zeek genera log strutturati anziché file PCAP, quindi usa strumenti di analisi dei log come `zeek-cut` per ispezionare tali log.<sup>[[15]](#references)[[16]](#references)</sup>

### Informazioni sulle connessioni

Gli esempi riportati di seguito usano `zeek-cut` per selezionare campi denominati dai log TSV, quindi strumenti Unix standard per classificare e contare le connessioni; RITA può inoltre acquisire i log Zeek per analizzare connessioni di lunga durata, beaconing e tunneling DNS.<sup>[[16]](#references)[[17]](#references)</sup>
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
### Informazioni DNS
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
## Altri trucchi per l'analisi dei pcap


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

- [1] [Wireshark User's Guide: Apertura dei file di cattura](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - servizio online di riparazione pcap / pcapng](https://f00l.de/hacking/pcapfix.php)
- [3] [Panoramica dell'API v3 di VirusTotal](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [A-Packets PCAP Analyzer](https://apackets.com/)
- [6] [Xplico - Informazioni](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [NetWitness Investigator Freeware](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [Repository di BruteShark](https://github.com/odedshimon/BruteShark)
- [10] [Manuale di Wireshark `capinfos`](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [Documentazione di ngrep](https://ngrep.sourceforge.net/usage.html)
- [12] [Repository di PCredz](https://github.com/lgandx/PCredz)
- [13] [Opzioni della riga di comando di Suricata](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [Repository di YaraPcap](https://github.com/kevthehermit/YaraPcap)
- [15] [Cos'è Zeek?](https://docs.zeek.org/en/master/about/what.html)
- [16] [Tutorial sui log di Zeek](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [Repository di RITA](https://github.com/activecm/rita)
- [18] [Documentazione di Wireshark `editcap`](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [Annuncio dell'API di caricamento di PacketTotal](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
