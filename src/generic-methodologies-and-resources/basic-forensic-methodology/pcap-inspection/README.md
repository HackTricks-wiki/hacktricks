# Inspeção de Pcap

> [!TIP]
> **PCAP** e **PCAPNG** são formatos de captura distintos; **PCAPNG é um sucessor flexível e extensível do PCAP**, mas o suporte varia entre as ferramentas. Se uma ferramenta não conseguir ler PCAPNG, converta-o para PCAP com o Wireshark ou outra ferramenta compatível.<sup>[[1]](#references)[[18]](#references)</sup>

## Ferramentas online para pcaps

- Se o cabeçalho do seu pcap estiver **corrompido**, tente **corrigi-lo** usando: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php).<sup>[[2]](#references)</sup>
- Extraia **informações** e procure por **malware** dentro de um pcap no [**PacketTotal**](https://packettotal.com).<sup>[[19]](#references)</sup>
- Procure por **atividade maliciosa** usando [**www.virustotal.com**](https://www.virustotal.com) e [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com).<sup>[[3]](#references)[[4]](#references)</sup>
- **Análise completa de pcap pelo navegador em** [**https://apackets.com/**](https://apackets.com/).<sup>[[5]](#references)</sup>

## Extrair informações

As ferramentas a seguir são úteis para extrair estatísticas, arquivos etc.

### Wireshark

> [!TIP]
> **Se você pretende analisar um PCAP, basicamente precisa saber como usar o Wireshark**

Você pode encontrar alguns truques do Wireshark em:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Análise de pcap pelo navegador.<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico) é uma ferramenta de network-forensics semelhante ao Unix que decodifica arquivos PCAP e pode extrair emails via POP/IMAP/SMTP, conteúdos HTTP, chamadas SIP VoIP, dados FTP e dados TFTP.<sup>[[6]](#references)</sup>

**Instalação**
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

Depois, crie um **novo caso**, crie uma **nova sessão** dentro do caso e **faça upload do arquivo pcap**.

### NetworkMiner

Assim como o Xplico, o [**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) analisa o tráfego PCAP para extrair artefatos como arquivos, imagens, e-mails e senhas, além de agregar informações sobre hosts; sua edição gratuita é voltada principalmente para Windows.<sup>[[7]](#references)</sup>

### NetWitness Investigator

Você pode baixar o [**NetWitness Investigator daqui**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(ele funciona no Windows)**.\
O fornecedor descreve o freeware como uma ferramenta interativa de análise de sessões de rede para a triagem de atividades maliciosas e atualmente disponibiliza o acesso por meio de um formulário de contato.<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

Os módulos documentados do BruteShark podem analisar credenciais de HTTP, FTP, Telnet, IMAP e SMTP, exportar hashes de autenticação Kerberos, NTLM, CRAM-MD5 e HTTP-Digest para o Hashcat, mapear nós e usuários da rede, extrair consultas DNS, reconstruir sessões TCP/UDP e extrair arquivos.<sup>[[9]](#references)</sup>

### Capinfos

O `capinfos` do Wireshark imprime, por padrão, um relatório detalhado para um arquivo de captura.<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

`ngrep` pesquisa payloads de pacotes com expressões regulares e aceita filtros BPF; `-I` lê um arquivo de captura compatível com pcap.<sup>[[11]](#references)</sup> O exemplo combina esses recursos para pesquisar uma solicitação HTTP no tráfego selecionado.
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Usar técnicas comuns de carving pode ser útil para extrair arquivos e informações do pcap:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturando credenciais

Você pode usar o [PCredz](https://github.com/lgandx/PCredz) para analisar credenciais de um arquivo PCAP armazenado ou de uma interface ativa.<sup>[[12]](#references)</sup>

## Verificar Exploits/Malware

### Suricata

**Instalação e configuração**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Verificar pcap**

A opção `-r` do Suricata reproduz um PCAP no modo offline; neste exemplo, `-k none` desativa as verificações de checksum, `-v` aumenta o nível de logging e `-l` seleciona o diretório de logs.<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) processa streams HTTP de arquivos PCAP, opcionalmente descompacta streams gzip, verifica os arquivos extraídos com YARA, grava `report.txt` e pode salvar os arquivos correspondentes em um diretório.<sup>[[14]](#references)</sup>

### Análise de Malware

Verifique se consegue encontrar alguma fingerprint de um malware conhecido:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) é um analisador passivo e open-source de tráfego de rede, usado como um Network Security Monitor (NSM) e para análises mais amplas de tráfego, incluindo medição de desempenho e troubleshooting.<sup>[[15]](#references)</sup>

O Zeek gera logs estruturados em vez de arquivos PCAP; portanto, use ferramentas de análise de logs, como `zeek-cut`, para inspecionar esses logs.<sup>[[15]](#references)[[16]](#references)</sup>

### Informações de Conexões

Os exemplos abaixo usam `zeek-cut` para selecionar campos nomeados de logs TSV e, em seguida, ferramentas Unix padrão para classificar e contar conexões; o RITA também pode ingerir logs do Zeek para análises de conexões longas, beaconing e DNS tunneling.<sup>[[16]](#references)[[17]](#references)</sup>
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
### Informações de DNS
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
## Outros truques de análise de pcap


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

- [1] [Guia do usuário do Wireshark: abrir arquivos de captura](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - serviço online de reparo de pcap / pcapng](https://f00l.de/hacking/pcapfix.php)
- [3] [Visão geral da API v3 do VirusTotal](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [Analisador de PCAP A-Packets](https://apackets.com/)
- [6] [Xplico - Sobre](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [Freeware NetWitness Investigator](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [Repositório do BruteShark](https://github.com/odedshimon/BruteShark)
- [10] [Manual do Wireshark `capinfos`](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [Documentação do ngrep](https://ngrep.sourceforge.net/usage.html)
- [12] [Repositório do PCredz](https://github.com/lgandx/PCredz)
- [13] [Opções de linha de comando do Suricata](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [Repositório do YaraPcap](https://github.com/kevthehermit/YaraPcap)
- [15] [O que é o Zeek?](https://docs.zeek.org/en/master/about/what.html)
- [16] [Tutorial de logs do Zeek](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [Repositório do RITA](https://github.com/activecm/rita)
- [18] [Documentação do Wireshark `editcap`](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [Anúncio da API de upload do PacketTotal](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
