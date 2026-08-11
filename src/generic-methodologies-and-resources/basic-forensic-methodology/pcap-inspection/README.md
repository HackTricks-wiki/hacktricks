# Inspection des Pcap

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> **PCAP** et **PCAPNG** sont des formats de capture distincts ; **PCAPNG est un successeur flexible et extensible de PCAP**, mais la prise en charge varie selon les outils. Si un outil ne peut pas lire le format PCAPNG, convertissez-le au format PCAP avec Wireshark ou un autre outil compatible.<sup>[[1]](#references)[[18]](#references)</sup>

## Outils en ligne pour les pcaps

- Si l'en-tête de votre pcap est **endommagé**, vous devriez essayer de le **réparer** avec : [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php).<sup>[[2]](#references)</sup>
- Extrayez des **informations** et recherchez des **malware** dans un pcap avec [**PacketTotal**](https://packettotal.com).<sup>[[19]](#references)</sup>
- Recherchez des **activités malveillantes** avec [**www.virustotal.com**](https://www.virustotal.com) et [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com).<sup>[[3]](#references)[[4]](#references)</sup>
- **Analyse complète d'un pcap depuis le navigateur avec** [**https://apackets.com/**](https://apackets.com/).<sup>[[5]](#references)</sup>

## Extraire des informations

Les outils suivants sont utiles pour extraire des statistiques, des fichiers, etc.

### Wireshark

> [!TIP]
> **Si vous allez analyser un PCAP, vous devez essentiellement savoir utiliser Wireshark**

Vous trouverez quelques astuces Wireshark dans :


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Analyse de pcap depuis le navigateur.<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico) est un outil de network-forensics de type Unix qui décode les fichiers PCAP et peut extraire des e-mails via POP/IMAP/SMTP, du contenu HTTP, des appels SIP VoIP, ainsi que des données FTP et TFTP.<sup>[[6]](#references)</sup>

**Installer**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Exécuter**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Accédez à _**127.0.0.1:9876**_ avec les identifiants _**xplico:xplico**_

Créez ensuite un **nouveau case**, créez une **nouvelle session** dans le case, puis **uploadez** le fichier **pcap**.

### NetworkMiner

Comme Xplico, [**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) analyse le trafic PCAP pour extraire des artefacts tels que des fichiers, des images, des e-mails et des mots de passe, et il rassemble les informations sur les hôtes ; son édition gratuite est principalement destinée à Windows.<sup>[[7]](#references)</sup>

### NetWitness Investigator

Vous pouvez télécharger [**NetWitness Investigator ici**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(il fonctionne sous Windows)**.\
Le fournisseur décrit ce logiciel gratuit comme un outil interactif d’analyse des sessions réseau destiné au triage des activités malveillantes et propose actuellement un accès via un formulaire de contact.<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

Les modules documentés de BruteShark peuvent analyser les identifiants dans HTTP, FTP, Telnet, IMAP et SMTP, exporter les hashes d’authentification Kerberos, NTLM, CRAM-MD5 et HTTP-Digest pour Hashcat, cartographier les nœuds et les utilisateurs du réseau, extraire les requêtes DNS, reconstruire les sessions TCP/UDP et extraire des fichiers.<sup>[[9]](#references)</sup>

### Capinfos

Le `capinfos` de Wireshark affiche par défaut un rapport détaillé pour un fichier de capture.<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

`ngrep` recherche les charges utiles des paquets avec des expressions régulières et accepte les filtres BPF ; `-I` lit un fichier de capture compatible avec pcap.<sup>[[11]](#references)</sup> L’exemple combine ces fonctionnalités pour rechercher une requête HTTP dans le trafic sélectionné.
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

L'utilisation de techniques courantes de carving peut être utile pour extraire des fichiers et des informations du pcap :


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capture de credentials

Vous pouvez utiliser [PCredz](https://github.com/lgandx/PCredz) pour analyser les credentials depuis un fichier PCAP enregistré ou une interface en direct.<sup>[[12]](#references)</sup>

## Vérifier les Exploits/Malware

### Suricata

**Installation et configuration**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Vérifier le pcap**

L'option `-r` de Suricata rejoue un PCAP en mode hors ligne ; dans cet exemple, `-k none` désactive les vérifications de checksum, `-v` augmente la journalisation et `-l` sélectionne le répertoire des logs.<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) traite les flux HTTP des fichiers PCAP, décompresse éventuellement les flux gzip, analyse les fichiers extraits avec YARA, écrit `report.txt` et peut enregistrer les fichiers correspondants dans un répertoire.<sup>[[14]](#references)</sup>

### Analyse de malware

Vérifiez si vous pouvez trouver une quelconque empreinte d'un malware connu :


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) est un analyseur passif et open source du trafic réseau, utilisé comme Network Security Monitor (NSM) et pour l'analyse plus générale du trafic, notamment la mesure des performances et le dépannage.<sup>[[15]](#references)</sup>

Zeek génère des journaux structurés plutôt que des fichiers PCAP. Utilisez donc des outils d'analyse de journaux tels que `zeek-cut` pour les examiner.<sup>[[15]](#references)[[16]](#references)</sup>

### Informations sur les connexions

Les exemples ci-dessous utilisent `zeek-cut` pour sélectionner des champs nommés dans les journaux TSV, puis des outils Unix standard pour classer et compter les connexions ; RITA peut également ingérer les journaux Zeek pour analyser les connexions longues, le beaconing et le tunneling DNS.<sup>[[16]](#references)[[17]](#references)</sup>
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
### Informations DNS
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
## Autres astuces d'analyse pcap


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

- [1] [Guide de l'utilisateur de Wireshark : ouvrir des fichiers de capture](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - service de réparation pcap / pcapng en ligne](https://f00l.de/hacking/pcapfix.php)
- [3] [Vue d'ensemble de l'API VirusTotal v3](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [A-Packets PCAP Analyzer](https://apackets.com/)
- [6] [Xplico - À propos](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [NetWitness Investigator Freeware](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [Dépôt BruteShark](https://github.com/odedshimon/BruteShark)
- [10] [Manuel Wireshark `capinfos`](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [Documentation ngrep](https://ngrep.sourceforge.net/usage.html)
- [12] [Dépôt PCredz](https://github.com/lgandx/PCredz)
- [13] [Options de ligne de commande Suricata](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [Dépôt YaraPcap](https://github.com/kevthehermit/YaraPcap)
- [15] [Qu'est-ce que Zeek ?](https://docs.zeek.org/en/master/about/what.html)
- [16] [Tutoriel sur les logs Zeek](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [Dépôt RITA](https://github.com/activecm/rita)
- [18] [Documentation Wireshark `editcap`](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [Annonce de l'API d'upload de PacketTotal](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
