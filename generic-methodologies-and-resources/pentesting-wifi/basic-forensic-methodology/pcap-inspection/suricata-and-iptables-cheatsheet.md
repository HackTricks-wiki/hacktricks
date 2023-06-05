# Cheatsheet de Suricata e Iptables

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Iptables

### Cadenas

Las cadenas de Iptables son simplemente listas de reglas, procesadas en orden. Siempre encontrarás las siguientes 3, pero otras como NAT también pueden ser compatibles.

* **Input** - Esta cadena se utiliza para controlar el comportamiento de las conexiones entrantes.
* **Forward** - Esta cadena se utiliza para conexiones entrantes que no se entregan localmente. Piensa en un enrutador: los datos siempre se envían a él, pero rara vez están destinados al enrutador en sí; los datos se reenvían a su destino. A menos que estés haciendo algún tipo de enrutamiento, NAT o algo más en tu sistema que requiera reenvío, ni siquiera usarás esta cadena.
* **Output** - Esta cadena se utiliza para conexiones salientes.
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

### Instalación y Configuración
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
### Definiciones de Reglas

Una regla/firma consiste en lo siguiente:

* La **acción**, determina lo que sucede cuando la firma coincide.
* El **encabezado**, define el protocolo, las direcciones IP, los puertos y la dirección de la regla.
* Las **opciones de la regla**, definen los detalles de la regla.

![](<../../../.gitbook/assets/image (642) (3).png>)

#### **Las acciones válidas son**

* alerta - generar una alerta
* pass - detener la inspección adicional del paquete
* **drop** - descartar el paquete y generar una alerta
* **reject** - enviar un error RST/ICMP inalcanzable al remitente del paquete coincidente.
* rejectsrc - lo mismo que _reject_
* rejectdst - enviar un paquete de error RST/ICMP al receptor del paquete coincidente.
* rejectboth - enviar paquetes de error RST/ICMP a ambos lados de la conversación.

#### **Protocolos**

* tcp (para tráfico tcp)
* udp
* icmp
* ip (ip significa "todos" o "cualquier")
* _protocolos de capa 7_: http, ftp, tls, smb, dns, ssh... (más en la [**documentación**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Direcciones de origen y destino

Admite rangos de direcciones IP, negaciones y una lista de direcciones:

| Ejemplo                        | Significado                                  |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | Cualquier dirección IP excepto 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]           | Cualquier dirección IP excepto 1.1.1.1 y 1.1.1.2 |
| $HOME\_NET                     | Su configuración de HOME\_NET en yaml        |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET y no HOME\_NET          |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24 excepto por 10.0.0.5          |

#### Puertos de origen y destino

Admite rangos de puertos, negaciones y listas de puertos

| Ejemplo         | Significado                                |
| --------------- | -------------------------------------- |
| any             | cualquier dirección                            |
| \[80, 81, 82]   | puerto 80, 81 y 82                     |
| \[80: 82]       | Rango desde 80 hasta 82                  |
| \[1024: ]       | Desde 1024 hasta el número de puerto más alto |
| !80             | Cualquier puerto excepto 80                      |
| \[80:100,!99]   | Rango de 80 a 100 pero excluyendo el 99 |
| \[1:80,!\[2,4]] | Rango de 1 a 80, excepto los puertos 2 y 4  |

#### Dirección

Es posible indicar la dirección de la regla de comunicación que se está aplicando:
```
source -> destination
source <> destination  (both directions)
```
#### Palabras clave

Hay **cientos de opciones** disponibles en Suricata para buscar el **paquete específico** que estás buscando, aquí se mencionará si se encuentra algo interesante. ¡Consulta la [**documentación**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) para más información!
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
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
