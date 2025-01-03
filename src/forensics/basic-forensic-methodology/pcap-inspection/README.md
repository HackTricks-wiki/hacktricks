# Inspección de Pcap

{{#include ../../../banners/hacktricks-training.md}}

> [!NOTE]
> Una nota sobre **PCAP** vs **PCAPNG**: hay dos versiones del formato de archivo PCAP; **PCAPNG es más nuevo y no es compatible con todas las herramientas**. Es posible que necesite convertir un archivo de PCAPNG a PCAP usando Wireshark u otra herramienta compatible, para poder trabajar con él en algunas otras herramientas.

## Herramientas en línea para pcaps

- Si el encabezado de su pcap está **dañado**, debe intentar **repararlo** usando: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- Extraiga **información** y busque **malware** dentro de un pcap en [**PacketTotal**](https://packettotal.com)
- Busque **actividad maliciosa** usando [**www.virustotal.com**](https://www.virustotal.com) y [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Extraer Información

Las siguientes herramientas son útiles para extraer estadísticas, archivos, etc.

### Wireshark

> [!NOTE]
> **Si va a analizar un PCAP, básicamente debe saber cómo usar Wireshark**

Puede encontrar algunos trucos de Wireshark en:

{{#ref}}
wireshark-tricks.md
{{#endref}}

### Marco Xplico

[**Xplico** ](https://github.com/xplico/xplico)_(solo linux)_ puede **analizar** un **pcap** y extraer información de él. Por ejemplo, de un archivo pcap, Xplico extrae cada correo electrónico (protocolos POP, IMAP y SMTP), todo el contenido HTTP, cada llamada VoIP (SIP), FTP, TFTP, y así sucesivamente.

**Instalar**
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
Acceso a _**127.0.0.1:9876**_ con credenciales _**xplico:xplico**_

Luego crea un **nuevo caso**, crea una **nueva sesión** dentro del caso y **sube el archivo pcap**.

### NetworkMiner

Al igual que Xplico, es una herramienta para **analizar y extraer objetos de pcaps**. Tiene una edición gratuita que puedes **descargar** [**aquí**](https://www.netresec.com/?page=NetworkMiner). Funciona con **Windows**.\
Esta herramienta también es útil para obtener **otra información analizada** de los paquetes para poder saber qué estaba sucediendo de una manera **más rápida**.

### NetWitness Investigator

Puedes descargar [**NetWitness Investigator desde aquí**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Funciona en Windows)**.\
Esta es otra herramienta útil que **analiza los paquetes** y organiza la información de una manera útil para **saber qué está sucediendo dentro**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

- Extracción y codificación de nombres de usuario y contraseñas (HTTP, FTP, Telnet, IMAP, SMTP...)
- Extraer hashes de autenticación y crackearlos usando Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
- Construir un diagrama de red visual (Nodos de red y usuarios)
- Extraer consultas DNS
- Reconstruir todas las sesiones TCP y UDP
- File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Si estás **buscando** **algo** dentro del pcap, puedes usar **ngrep**. Aquí hay un ejemplo usando los filtros principales:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Usar técnicas comunes de carving puede ser útil para extraer archivos e información del pcap:

{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### Capturing credentials

Puedes usar herramientas como [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) para analizar credenciales de un pcap o de una interfaz en vivo.

## Check Exploits/Malware

### Suricata

**Instalar y configurar**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Ver pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) es una herramienta que

- Lee un archivo PCAP y extrae flujos Http.
- gzip descomprime cualquier flujo comprimido.
- Escanea cada archivo con yara.
- Escribe un report.txt.
- Opcionalmente guarda archivos coincidentes en un directorio.

### Análisis de Malware

Verifica si puedes encontrar alguna huella de un malware conocido:

{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) es un analizador de tráfico de red pasivo y de código abierto. Muchos operadores utilizan Zeek como un Monitor de Seguridad de Red (NSM) para apoyar investigaciones de actividades sospechosas o maliciosas. Zeek también soporta una amplia gama de tareas de análisis de tráfico más allá del dominio de la seguridad, incluyendo medición de rendimiento y solución de problemas.

Básicamente, los registros creados por `zeek` no son **pcaps**. Por lo tanto, necesitarás usar **otras herramientas** para analizar los registros donde se encuentra la **información** sobre los pcaps.

### Información de Conexiones
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
## Otras trucos de análisis de pcap

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
