# Inspección de Pcap

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro crucial para profesionales de tecnología y ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
Una nota sobre **PCAP** vs **PCAPNG**: existen dos versiones del formato de archivo PCAP; **PCAPNG es más nuevo y no es compatible con todas las herramientas**. Es posible que necesites convertir un archivo de PCAPNG a PCAP usando Wireshark u otra herramienta compatible, para poder trabajar con él en algunas otras herramientas.
{% endhint %}

## Herramientas en línea para pcaps

* Si el encabezado de tu pcap está **dañado** debes intentar **repararlo** usando: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* Extrae **información** y busca **malware** dentro de un pcap en [**PacketTotal**](https://packettotal.com)
* Busca **actividad maliciosa** utilizando [**www.virustotal.com**](https://www.virustotal.com) y [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Extraer Información

Las siguientes herramientas son útiles para extraer estadísticas, archivos, etc.

### Wireshark

{% hint style="info" %}
**Si vas a analizar un PCAP básicamente debes saber cómo usar Wireshark**
{% endhint %}

Puedes encontrar algunos trucos de Wireshark en:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### Marco de Xplico

[**Xplico** ](https://github.com/xplico/xplico)_(solo en linux)_ puede **analizar** un **pcap** y extraer información de él. Por ejemplo, de un archivo pcap, Xplico extrae cada correo electrónico (protocolos POP, IMAP y SMTP), todos los contenidos HTTP, cada llamada VoIP (SIP), FTP, TFTP, y más.

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

Luego crea un **nuevo caso**, crea una **nueva sesión** dentro del caso y **sube el archivo pcap**.

### NetworkMiner

Al igual que Xplico, es una herramienta para **analizar y extraer objetos de pcaps**. Tiene una edición gratuita que puedes **descargar** [**aquí**](https://www.netresec.com/?page=NetworkMiner). Funciona con **Windows**.\
Esta herramienta también es útil para obtener **otra información analizada** de los paquetes para poder saber qué estaba sucediendo de una manera **más rápida**.

### NetWitness Investigator

Puedes descargar [**NetWitness Investigator desde aquí**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Funciona en Windows)**.\
Esta es otra herramienta útil que **analiza los paquetes** y ordena la información de una manera útil para **saber qué está sucediendo por dentro**.

![](<../../../.gitbook/assets/image (567) (1).png>)

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Extracción y codificación de nombres de usuario y contraseñas (HTTP, FTP, Telnet, IMAP, SMTP...)
* Extracción de hashes de autenticación y crackeo con Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Construcción de un diagrama visual de red (Nodos de red y usuarios)
* Extracción de consultas DNS
* Reconstrucción de todas las sesiones TCP y UDP
* Tallado de archivos

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Si estás **buscando** algo dentro del pcap, puedes usar **ngrep**. Aquí tienes un ejemplo usando los filtros principales:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Tallado

El uso de técnicas comunes de tallado puede ser útil para extraer archivos e información del pcap:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Captura de credenciales

Puedes utilizar herramientas como [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) para analizar credenciales de un pcap o de una interfaz en vivo.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro crucial para profesionales de tecnología y ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## Verificar Exploits/Malware

### Suricata

**Instalación y configuración**
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

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) es una herramienta que

* Lee un archivo PCAP y extrae flujos Http.
* Descomprime cualquier flujo comprimido con gzip.
* Escanea cada archivo con yara.
* Escribe un reporte.txt.
* Opcionalmente guarda los archivos coincidentes en un directorio.

### Análisis de Malware

Verifique si puede encontrar alguna huella de un malware conocido:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> Zeek es un analizador de tráfico de red de código abierto y pasivo. Muchos operadores utilizan Zeek como Monitor de Seguridad de Red (NSM) para respaldar investigaciones de actividad sospechosa o maliciosa. Zeek también admite una amplia gama de tareas de análisis de tráfico más allá del dominio de la seguridad, incluida la medición del rendimiento y la resolución de problemas.

Básicamente, los registros creados por `zeek` no son **pcaps**. Por lo tanto, necesitarás usar **otras herramientas** para analizar los registros donde se encuentra la **información** sobre los pcaps.
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

{% content-ref url="dnscat-exfiltration.md" %}
[dnscat-exfiltration.md](dnscat-exfiltration.md)
{% endcontent-ref %}

{% content-ref url="wifi-pcap-analysis.md" %}
[wifi-pcap-analysis.md](wifi-pcap-analysis.md)
{% endcontent-ref %}

{% content-ref url="usb-keystrokes.md" %}
[usb-keystrokes.md](usb-keystrokes.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro clave para profesionales de la tecnología y ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
