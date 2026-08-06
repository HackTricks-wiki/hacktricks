# Hoja de trucos de Suricata e Iptables

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Cadenas

En iptables, las listas de reglas conocidas como cadenas se procesan secuencialmente. Entre ellas, hay tres cadenas principales presentes universalmente, mientras que otras, como NAT, pueden estar disponibles dependiendo de las capacidades del sistema.

- **Cadena de entrada**: Se utiliza para gestionar el comportamiento de las conexiones entrantes.
- **Cadena de reenvío**: Se emplea para gestionar las conexiones entrantes que no están destinadas al sistema local. Esto es habitual en dispositivos que actúan como routers, donde los datos recibidos deben reenviarse a otro destino. Esta cadena es relevante principalmente cuando el sistema participa en actividades de routing, NATing o similares.
- **Cadena de salida**: Se dedica a regular las conexiones salientes.

Estas cadenas garantizan el procesamiento ordenado del tráfico de red, permitiendo especificar reglas detalladas que gobiernan el flujo de datos hacia dentro, a través de y fuera de un sistema.
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
```bash
# Install details from: https://suricata.readthedocs.io/en/suricata-6.0.0/install.html#install-binary-packages
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
suricata-update
suricata-update list-sources #List sources of the rules
suricata-update enable-source et/open #Add et/open rulesets
suricata-update
## To use the dowloaded rules update the following line in /etc/suricata/suricata.yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
- suricata.rules

# Run
## Add rules in /etc/suricata/rules/suricata.rules
systemctl suricata start
suricata -c /etc/suricata/suricata.yaml -i eth0


# Reload rules
suricatasc -c ruleset-reload-nonblocking
## or set the follogin in /etc/suricata/suricata.yaml
detect-engine:
- rule-reload: true

# Validate suricata config
suricata -T -c /etc/suricata/suricata.yaml -v

# Configure suricata as IPs
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
### Definiciones de Rules

[De la documentación:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Una rule/signature consta de lo siguiente:

- La **action**, determina qué ocurre cuando la signature coincide.
- El **header**, define el protocolo, las direcciones IP, los puertos y la dirección de la rule.
- Las **rule options**, definen los detalles específicos de la rule.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Las acciones válidas son**

- alert - generar una alerta
- pass - detener la inspección adicional del paquete
- **drop** - descartar el paquete y generar una alerta
- **reject** - enviar un error RST/ICMP unreachable al emisor del paquete coincidente.
- rejectsrc - igual que _reject_
- rejectdst - enviar un paquete de error RST/ICMP al receptor del paquete coincidente.
- rejectboth - enviar paquetes de error RST/ICMP a ambos lados de la conversación.

#### **Protocols**

- tcp (para tráfico tcp)
- udp
- icmp
- ip (ip significa ‘all’ o ‘any’)
- _layer7 protocols_: http, ftp, tls, smb, dns, ssh... (más información en la [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Direcciones de origen y destino

Admite rangos de IP, negaciones y una lista de direcciones:

| Ejemplo                       | Significado                                  |
| ----------------------------- | -------------------------------------------- |
| ! 1.1.1.1                     | Toda dirección IP excepto 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]          | Toda dirección IP excepto 1.1.1.1 y 1.1.1.2 |
| $HOME_NET                     | Tu configuración de HOME_NET en yaml         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET y no HOME_NET            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 excepto 10.0.0.5          |

#### Puertos de origen y destino

Admite rangos de puertos, negaciones y listas de puertos

| Ejemplo         | Significado                                |
| --------------- | -------------------------------------- |
| any             | cualquier dirección                            |
| \[80, 81, 82]   | puertos 80, 81 y 82                     |
| \[80: 82]       | Rango de 80 a 82                  |
| \[1024: ]       | De 1024 hasta el número de puerto más alto |
| !80             | Todos los puertos excepto el 80                      |
| \[80:100,!99]   | Rango de 80 a 100, excepto el 99 |
| \[1:80,!\[2,4]] | Rango de 1 a 80, excepto los puertos 2 y 4  |

#### Dirección

Es posible indicar la dirección de la comunicación a la que se aplica la regla:
```
source -> destination
source <> destination  (both directions)
```
#### Palabras clave

Hay **cientos de opciones** disponibles en Suricata para buscar el **paquete específico** que estás buscando; aquí se mencionará si se encuentra algo interesante. ¡Consulta la [**documentación** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)para obtener más información!
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
{{#include ../../../banners/hacktricks-training.md}}
