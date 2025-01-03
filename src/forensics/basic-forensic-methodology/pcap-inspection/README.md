# Inspeção de Pcap

{{#include ../../../banners/hacktricks-training.md}}

> [!NOTE]
> Uma nota sobre **PCAP** vs **PCAPNG**: existem duas versões do formato de arquivo PCAP; **PCAPNG é mais novo e não é suportado por todas as ferramentas**. Você pode precisar converter um arquivo de PCAPNG para PCAP usando o Wireshark ou outra ferramenta compatível, para poder trabalhar com ele em algumas outras ferramentas.

## Ferramentas online para pcaps

- Se o cabeçalho do seu pcap estiver **corrompido**, você deve tentar **corrigi-lo** usando: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- Extraia **informações** e procure por **malware** dentro de um pcap em [**PacketTotal**](https://packettotal.com)
- Procure por **atividade maliciosa** usando [**www.virustotal.com**](https://www.virustotal.com) e [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Extrair Informações

As seguintes ferramentas são úteis para extrair estatísticas, arquivos, etc.

### Wireshark

> [!NOTE]
> **Se você vai analisar um PCAP, basicamente deve saber como usar o Wireshark**

Você pode encontrar algumas dicas do Wireshark em:

{{#ref}}
wireshark-tricks.md
{{#endref}}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(apenas linux)_ pode **analisar** um **pcap** e extrair informações dele. Por exemplo, de um arquivo pcap, o Xplico extrai cada e-mail (protocolos POP, IMAP e SMTP), todo o conteúdo HTTP, cada chamada VoIP (SIP), FTP, TFTP, e assim por diante.

**Instalar**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Executar**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Acesse _**127.0.0.1:9876**_ com as credenciais _**xplico:xplico**_

Em seguida, crie um **novo caso**, crie uma **nova sessão** dentro do caso e **faça o upload** do arquivo pcap.

### NetworkMiner

Como o Xplico, é uma ferramenta para **analisar e extrair objetos de pcaps**. Tem uma edição gratuita que você pode **baixar** [**aqui**](https://www.netresec.com/?page=NetworkMiner). Funciona com **Windows**.\
Esta ferramenta também é útil para obter **outras informações analisadas** dos pacotes, a fim de saber o que estava acontecendo de uma forma **mais rápida**.

### NetWitness Investigator

Você pode baixar [**NetWitness Investigator daqui**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Funciona no Windows)**.\
Esta é outra ferramenta útil que **analisa os pacotes** e organiza as informações de uma maneira útil para **saber o que está acontecendo internamente**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- Extraindo e codificando nomes de usuários e senhas (HTTP, FTP, Telnet, IMAP, SMTP...)
- Extrair hashes de autenticação e quebrá-los usando Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- Construir um diagrama de rede visual (Nós e usuários da rede)
- Extrair consultas DNS
- Reconstruir todas as sessões TCP e UDP
- File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Se você está **procurando** **algo** dentro do pcap, pode usar **ngrep**. Aqui está um exemplo usando os principais filtros:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Usar técnicas comuns de carving pode ser útil para extrair arquivos e informações do pcap:

{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturando credenciais

Você pode usar ferramentas como [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) para analisar credenciais de um pcap ou de uma interface ao vivo.

## Verificar Exploits/Malware

### Suricata

**Instalar e configurar**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Verificar pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) é uma ferramenta que

- Lê um arquivo PCAP e extrai fluxos Http.
- gzip descomprime quaisquer fluxos comprimidos
- Escaneia cada arquivo com yara
- Escreve um report.txt
- Opcionalmente salva arquivos correspondentes em um diretório

### Análise de Malware

Verifique se você consegue encontrar alguma impressão digital de um malware conhecido:

{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) é um analisador de tráfego de rede passivo e de código aberto. Muitos operadores usam o Zeek como um Monitor de Segurança de Rede (NSM) para apoiar investigações de atividades suspeitas ou maliciosas. O Zeek também suporta uma ampla gama de tarefas de análise de tráfego além do domínio da segurança, incluindo medição de desempenho e solução de problemas.

Basicamente, os logs criados pelo `zeek` não são **pcaps**. Portanto, você precisará usar **outras ferramentas** para analisar os logs onde as **informações** sobre os pcaps estão.

### Informações de Conexões
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
### Informações DNS
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
## Outras dicas de análise de pcap

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
