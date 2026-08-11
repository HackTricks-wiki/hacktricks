# Chuleta de Suricata e Iptables

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chains

En iptables, cada chain es una lista secuencial de reglas que hacen coincidir paquetes. La tabla `filter` predeterminada tiene las chains integradas `INPUT`, `FORWARD` y `OUTPUT`; otras tablas, como `nat`, pueden estar disponibles según la configuración del kernel y los módulos cargados.<sup>[[1]](#references)</sup>

- **Input Chain**: Se utiliza para gestionar el comportamiento de las conexiones entrantes.
- **Forward Chain**: Se utiliza para gestionar las conexiones entrantes que no están destinadas al sistema local. Esto es habitual en dispositivos que actúan como routers, donde los datos recibidos deben reenviarse a otro destino. Esta chain es relevante principalmente cuando el sistema participa en tareas de routing, NATing o actividades similares.
- **Output Chain**: Está dedicada a regular las conexiones salientes.

Estas chains garantizan el procesamiento ordenado del tráfico de red y permiten especificar reglas detalladas que controlan el flujo de datos hacia un sistema, a través de él y desde él.

Los ejemplos de coincidencia de cadenas utilizan la coincidencia estándar `string`; la coincidencia distingue entre mayúsculas y minúsculas a menos que se proporcione `--icase`, y `--algo` selecciona la estrategia de búsqueda BM o KMP.<sup>[[2]](#references)</sup>
```bash
# Delete all rules
iptables -F

# List all rules
iptables -L
iptables -S

# Block IP addresses & ports
iptables -I INPUT -s ip1,ip2,ip3 -j DROP
iptables -I INPUT -p tcp --dport 443 -j DROP
iptables -I INPUT -s ip1,ip2 -p tcp --dport 443 -j DROP

# String based drop
## Strings are case sensitive (pretty easy to bypass if you want to check an SQLi for example)
iptables -I INPUT -p tcp --dport <port_listening> -m string --algo bm --string '<payload>' -j DROP
iptables -I OUTPUT -p tcp --sport <port_listening> -m string --algo bm --string 'CTF{' -j DROP
## You can also check for the hex, base64 and double base64 of the expected CTF flag chars

# Drop every input port except some
iptables -P INPUT DROP # Default to drop
iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT


# Persist Iptables
## Debian/Ubuntu:
apt-get install iptables-persistent
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
iptables-restore < /etc/iptables/rules.v4
##RHEL/CentOS:
iptables-save > /etc/sysconfig/iptables
ip6tables-save > /etc/sysconfig/ip6tables
iptables-restore < /etc/sysconfig/iptables
```
## Suricata

### Instalación y configuración

Los comandos de paquetes dependen de la distribución y la versión; la guía oficial de instalación documenta el PPA de Ubuntu, los backports de Debian, los paquetes RPM y la gestión del servicio systemd.<sup>[[3]](#references)</sup>
```bash
# Package installation details vary by distribution and release; see References.
# Ubuntu
add-apt-repository ppa:oisf/suricata-stable
apt-get update
apt-get install suricata

# Debian
echo "deb http://http.debian.net/debian buster-backports main" > \
/etc/apt/sources.list.d/backports.list
apt-get update
apt-get install suricata -t buster-backports

# CentOS
yum install epel-release
yum install suricata

# Get rules
suricata-update update-sources
suricata-update list-sources #List sources of the rules
suricata-update enable-source et/open #Add et/open rulesets
suricata-update
## To use the dowloaded rules update the following line in /etc/suricata/suricata.yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
- suricata.rules

# Run
## Add rules in /etc/suricata/rules/suricata.rules
systemctl start suricata
suricata -c /etc/suricata/suricata.yaml -i eth0


# Reload rules
suricatasc -c ruleset-reload-nonblocking

# Validate suricata config
suricata -T -c /etc/suricata/suricata.yaml -v

# Configure Suricata as an IPS
## Config drop to generate alerts
## Search for the following lines in /etc/suricata/suricata.yaml and remove comments:
- drop:
alerts: yes
flows: all

## Forward all packages to the queue where suricata can act as IPS
iptables -I INPUT -j NFQUEUE
iptables -I OUTPUT -j NFQUEUE

## Start suricata in IPS mode
suricata -c /etc/suricata/suricata.yaml  -q 0
### or modify the service config file as:
systemctl edit suricata.service

[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid -q 0 -vvv
Type=simple

systemctl daemon-reload
```
La secuencia de `suricata-update` sigue el flujo de trabajo documentado de Suricata para obtener, listar, habilitar y cargar fuentes de reglas.<sup>[[4]](#references)</sup> El comando `suricatasc` anterior es un método documentado de recarga de reglas mediante un Unix socket sin bloqueo.<sup>[[8]](#references)</sup> Las reglas de NFQUEUE envían el tráfico local de entrada/salida a Suricata, mientras que `-q 0` selecciona la cola 0 para el procesamiento inline.<sup>[[7]](#references)</sup>

### Definiciones de reglas

Una regla/firma de Suricata tiene tres partes.<sup>[[5]](#references)</sup>

- La **acción** especifica qué ocurre cuando la firma coincide.
- El **encabezado** selecciona el protocolo, las direcciones IP, los puertos y la dirección.
- Las **opciones de regla** definen los detalles específicos de la coincidencia.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Las acciones válidas son**

- alert - generar una alerta
- pass - detener la inspección adicional del paquete
- **drop** - descartar el paquete y generar una alerta
- **reject** - enviar un error RST/ICMP unreachable al remitente del paquete coincidente.
- rejectsrc - igual que _reject_
- rejectdst - enviar un paquete de error RST/ICMP al receptor del paquete coincidente.
- rejectboth - enviar paquetes de error RST/ICMP a ambos lados de la comunicación.

#### **Protocolos**

- tcp (para tráfico tcp)
- udp
- icmp
- ip (ip significa ‘all’ o ‘any’)
- _protocolos de layer7_: http, ftp, tls, smb, dns, ssh y otros.<sup>[[5]](#references)</sup>

#### Direcciones de origen y destino

Suricata admite rangos de IP, negación y listas de direcciones agrupadas.<sup>[[5]](#references)</sup>

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | Cada dirección IP excepto 1.1.1.1        |
| !\[1.1.1.1, 1.1.1.2]          | Cada dirección IP excepto 1.1.1.1 y 1.1.1.2 |
| $HOME_NET                     | Tu configuración de HOME_NET en yaml     |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET y no HOME_NET               |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 excepto 10.0.0.5             |

#### Puertos de origen y destino

Suricata admite rangos de puertos, negación y listas de puertos.<sup>[[5]](#references)</sup>

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | cualquier dirección                   |
| \[80, 81, 82]   | puertos 80, 81 y 82                    |
| \[80: 82]       | Rango de 80 a 82                       |
| \[1024: ]       | De 1024 hasta el número de puerto más alto |
| !80             | Todos los puertos excepto el 80        |
| \[80:100,!99]   | Rango de 80 a 100, excepto el 99       |
| \[1:80,!\[2,4]] | Rango de 1 a 80, excepto los puertos 2 y 4 |

#### Dirección

Las reglas de Suricata pueden especificar la dirección de comunicación que se está evaluando.<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### Palabras clave

Los ejemplos siguientes utilizan las palabras clave de reglas de Suricata, incluidos metadatos y opciones de IP, ICMP, payload y de la capa de aplicación; la documentación oficial de reglas cataloga estas familias y su sintaxis.<sup>[[6]](#references)[[9]](#references)</sup>
```bash
# Meta Keywords
msg: "description"; #Set a description to the rule
sid:123 #Set a unique ID to the rule
rev:1 #Rule revision number
config classification: not-suspicious,Not Suspicious Traffic,3 #Classify
reference: url, www.info.com #Reference
priority:1; #Set a priority
metadata: key value, key value; #Extra metadata

# Filter by geolocation
geoip: src,RU;

# ICMP type & Code
itype:<10;
icode:0

# Filter by string
content: "something"
content: |61 61 61| #Hex: AAA
content: "http|3A|//" #Mix string and hex
content: "abc"; nocase; #Case insensitive
reject tcp any any -> any any (msg: "php-rce"; content: "eval"; nocase; metadata: tag php-rce; sid:101; rev: 1;)

# Replaces string
## Content and replace string must have the same length
## The replace modifier is IPS-only and operates on individual packets
content:"abc"; replace: "def"
alert tcp any any -> any any (msg: "flag replace"; content: "CTF{a6st"; replace: "CTF{u798"; nocase; sid:100; rev: 1;)
## The replace works in both input and output packets
## But it only modifies the first match

# Filter by regex
pcre:"/<regex>/opts"
pcre:"/NICK .*USA.*[0-9]{3,}/i"
drop tcp any any -> any any (msg:"regex"; pcre:"/CTF\{[\w]{3}/i"; sid:10001;)

# Other examples
## Drop by port
drop tcp any any -> any 8000 (msg:"8000 port"; sid:1000;)
```
## References

- [1] [iptables(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Instalación — documentación de Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Gestión de reglas con Suricata-Update — documentación de Suricata 8.0.1](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Formato de reglas — documentación de Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Palabras clave de payload — documentación de Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Configuración de IPS/inline para Linux — documentación de Suricata 7.0.15](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Recarga de reglas — documentación de Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Reglas de Suricata — documentación de Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
