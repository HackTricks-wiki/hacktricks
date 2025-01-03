# Inspection de Pcap

{{#include ../../../banners/hacktricks-training.md}}

> [!NOTE]
> Une note sur **PCAP** vs **PCAPNG** : il existe deux versions du format de fichier PCAP ; **PCAPNG est plus récent et n'est pas pris en charge par tous les outils**. Vous devrez peut-être convertir un fichier de PCAPNG en PCAP en utilisant Wireshark ou un autre outil compatible, afin de pouvoir travailler avec dans certains autres outils.

## Outils en ligne pour les pcaps

- Si l'en-tête de votre pcap est **cassé**, vous devriez essayer de le **réparer** en utilisant : [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- Extraire des **informations** et rechercher des **malwares** à l'intérieur d'un pcap dans [**PacketTotal**](https://packettotal.com)
- Rechercher une **activité malveillante** en utilisant [**www.virustotal.com**](https://www.virustotal.com) et [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Extraire des informations

Les outils suivants sont utiles pour extraire des statistiques, des fichiers, etc.

### Wireshark

> [!NOTE]
> **Si vous allez analyser un PCAP, vous devez essentiellement savoir comment utiliser Wireshark**

Vous pouvez trouver quelques astuces Wireshark dans :

{{#ref}}
wireshark-tricks.md
{{#endref}}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(uniquement linux)_ peut **analyser** un **pcap** et extraire des informations à partir de celui-ci. Par exemple, à partir d'un fichier pcap, Xplico extrait chaque e-mail (protocoles POP, IMAP et SMTP), tout le contenu HTTP, chaque appel VoIP (SIP), FTP, TFTP, et ainsi de suite.

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

Ensuite, créez un **nouveau cas**, créez une **nouvelle session** à l'intérieur du cas et **téléchargez le fichier pcap**.

### NetworkMiner

Comme Xplico, c'est un outil pour **analyser et extraire des objets des pcaps**. Il a une édition gratuite que vous pouvez **télécharger** [**ici**](https://www.netresec.com/?page=NetworkMiner). Il fonctionne sous **Windows**.\
Cet outil est également utile pour obtenir **d'autres informations analysées** à partir des paquets afin de pouvoir savoir ce qui se passait de manière **plus rapide**.

### NetWitness Investigator

Vous pouvez télécharger [**NetWitness Investigator depuis ici**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Il fonctionne sous Windows)**.\
C'est un autre outil utile qui **analyse les paquets** et trie les informations de manière utile pour **savoir ce qui se passe à l'intérieur**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- Extraction et encodage des noms d'utilisateur et des mots de passe (HTTP, FTP, Telnet, IMAP, SMTP...)
- Extraire les hachages d'authentification et les craquer en utilisant Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- Construire un diagramme de réseau visuel (Nœuds et utilisateurs du réseau)
- Extraire les requêtes DNS
- Reconstruire toutes les sessions TCP et UDP
- File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Si vous **cherchez** **quelque chose** à l'intérieur du pcap, vous pouvez utiliser **ngrep**. Voici un exemple utilisant les filtres principaux :
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

L'utilisation de techniques de carving courantes peut être utile pour extraire des fichiers et des informations du pcap :

{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturing credentials

Vous pouvez utiliser des outils comme [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) pour analyser les identifiants à partir d'un pcap ou d'une interface en direct.

## Check Exploits/Malware

### Suricata

**Installer et configurer**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Vérifier pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) est un outil qui

- Lit un fichier PCAP et extrait les flux Http.
- gzip décompresse tous les flux compressés
- Scanne chaque fichier avec yara
- Écrit un rapport.txt
- Enregistre éventuellement les fichiers correspondants dans un répertoire

### Analyse de Malware

Vérifiez si vous pouvez trouver une empreinte d'un malware connu :

{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) est un analyseur de trafic réseau passif et open-source. De nombreux opérateurs utilisent Zeek comme Moniteur de Sécurité Réseau (NSM) pour soutenir les enquêtes sur des activités suspectes ou malveillantes. Zeek prend également en charge un large éventail de tâches d'analyse de trafic au-delà du domaine de la sécurité, y compris la mesure de performance et le dépannage.

En gros, les journaux créés par `zeek` ne sont pas des **pcaps**. Par conséquent, vous devrez utiliser **d'autres outils** pour analyser les journaux où se trouvent les **informations** sur les pcaps.

### Informations sur les Connexions
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

​

{{#include ../../../banners/hacktricks-training.md}}
