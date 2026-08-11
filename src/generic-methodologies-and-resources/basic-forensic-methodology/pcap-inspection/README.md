# Inspección de Pcap

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> **PCAP** y **PCAPNG** son formatos de captura distintos; **PCAPNG es un sucesor flexible y extensible de PCAP**, pero la compatibilidad varía según las herramientas. Si una herramienta no puede leer PCAPNG, conviértelo a PCAP con Wireshark u otra herramienta compatible.<sup>[[1]](#references)[[18]](#references)</sup>

## Herramientas online para pcaps

- Si la cabecera de tu pcap está **dañada**, deberías intentar **repararla** usando: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php).<sup>[[2]](#references)</sup>
- Extrae **información** y busca **malware** dentro de un pcap en [**PacketTotal**](https://packettotal.com).<sup>[[19]](#references)</sup>
- Busca **actividad maliciosa** usando [**www.virustotal.com**](https://www.virustotal.com) y [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com).<sup>[[3]](#references)[[4]](#references)</sup>
- **Análisis completo de pcap desde el navegador en** [**https://apackets.com/**](https://apackets.com/).<sup>[[5]](#references)</sup>

## Extraer información

Las siguientes herramientas son útiles para extraer estadísticas, archivos, etc.

### Wireshark

> [!TIP]
> **Si vas a analizar un PCAP, básicamente debes saber utilizar Wireshark**

Puedes encontrar algunos trucos de Wireshark en:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

Análisis de pcap desde el navegador.<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico) es una herramienta de network-forensics para sistemas tipo Unix que decodifica archivos PCAP y puede extraer correos electrónicos mediante POP/IMAP/SMTP, contenidos HTTP, llamadas SIP VoIP, datos FTP y datos TFTP.<sup>[[6]](#references)</sup>

**Instalación**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Ejecutar**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Accede a _**127.0.0.1:9876**_ con las credenciales _**xplico:xplico**_

Después, crea un **new case**, crea una **new session** dentro del caso y **upload the pcap** file.

### NetworkMiner

Al igual que Xplico, [**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) analiza el tráfico PCAP para extraer artefactos como archivos, imágenes, correos electrónicos y contraseñas, y agrega información de los hosts; su edición gratuita está destinada principalmente a Windows.<sup>[[7]](#references)</sup>

### NetWitness Investigator

Puedes descargar [**NetWitness Investigator from here**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(It works in Windows)**.\
El proveedor describe el freeware como una herramienta interactiva de análisis de sesiones de red para la clasificación de actividades maliciosas y actualmente ofrece acceso mediante un formulario de contacto.<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

Los módulos documentados de BruteShark pueden analizar credenciales de HTTP, FTP, Telnet, IMAP y SMTP; exportar hashes de autenticación Kerberos, NTLM, CRAM-MD5 y HTTP-Digest para Hashcat; mapear nodos y usuarios de la red; extraer consultas DNS; reconstruir sesiones TCP/UDP y extraer archivos.<sup>[[9]](#references)</sup>

### Capinfos

El `capinfos` de Wireshark muestra de forma predeterminada un informe detallado de un archivo de captura.<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

`ngrep` busca cargas útiles de paquetes con expresiones regulares y acepta filtros BPF; `-I` lee un archivo de captura compatible con pcap.<sup>[[11]](#references)</sup> El ejemplo combina esas funciones para buscar una solicitud HTTP en el tráfico seleccionado.
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

El uso de técnicas comunes de carving puede ser útil para extraer archivos e información del pcap:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Captura de credenciales

Puedes usar [PCredz](https://github.com/lgandx/PCredz) para analizar credenciales de un archivo PCAP almacenado o de una interfaz activa.<sup>[[12]](#references)</sup>

## Comprobar Exploits/Malware

### Suricata

**Instalación y configuración**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Comprobar pcap**

La opción `-r` de Suricata reproduce un PCAP en modo offline; en este ejemplo, `-k none` desactiva las comprobaciones de checksum, `-v` aumenta el registro y `-l` selecciona el directorio de logs.<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) procesa streams HTTP de archivos PCAP, descomprime opcionalmente los streams gzip, analiza los archivos extraídos con YARA, escribe `report.txt` y puede guardar los archivos coincidentes en un directorio.<sup>[[14]](#references)</sup>

### Análisis de Malware

Comprueba si puedes encontrar alguna huella digital de un malware conocido:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) es un analizador pasivo y open-source del tráfico de red, utilizado como Network Security Monitor (NSM) y para un análisis más amplio del tráfico, incluida la medición del rendimiento y la resolución de problemas.<sup>[[15]](#references)</sup>

Zeek genera logs estructurados en lugar de archivos PCAP, por lo que debes usar herramientas de análisis de logs como `zeek-cut` para inspeccionarlos.<sup>[[15]](#references)[[16]](#references)</sup>

### Información de las conexiones

Los ejemplos siguientes utilizan `zeek-cut` para seleccionar campos con nombre de logs TSV y, posteriormente, herramientas estándar de Unix para clasificar y contar conexiones; RITA también puede ingerir logs de Zeek para analizar conexiones de larga duración, beaconing y DNS-tunneling.<sup>[[16]](#references)[[17]](#references)</sup>
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
### Información de DNS
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
## Otros trucos de análisis de pcap


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

- [1] [Guía del usuario de Wireshark: abrir archivos de captura](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - servicio online de reparación de pcap / pcapng](https://f00l.de/hacking/pcapfix.php)
- [3] [Descripción general de la API v3 de VirusTotal](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [Analizador de PCAP de A-Packets](https://apackets.com/)
- [6] [Xplico - Acerca de](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [NetWitness Investigator Freeware](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [Repositorio de BruteShark](https://github.com/odedshimon/BruteShark)
- [10] [Manual de `capinfos` de Wireshark](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [Documentación de ngrep](https://ngrep.sourceforge.net/usage.html)
- [12] [Repositorio de PCredz](https://github.com/lgandx/PCredz)
- [13] [Opciones de línea de comandos de Suricata](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [Repositorio de YaraPcap](https://github.com/kevthehermit/YaraPcap)
- [15] [¿Qué es Zeek?](https://docs.zeek.org/en/master/about/what.html)
- [16] [Tutorial sobre los logs de Zeek](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [Repositorio de RITA](https://github.com/activecm/rita)
- [18] [Documentación de `editcap` de Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [Anuncio de la API de carga de PacketTotal](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
