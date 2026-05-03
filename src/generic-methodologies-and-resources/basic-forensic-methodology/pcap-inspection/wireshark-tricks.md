# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Mejora tus habilidades de Wireshark

### Tutorials

Los siguientes tutorials son increíbles para aprender algunos trucos básicos útiles:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

Haciendo clic en _**Analyze** --> **Expert Information**_ tendrás una **visión general** de lo que está ocurriendo en los paquetes **analizados**:

![](<../../../images/image (256).png>)

**Resolved Addresses**

En _**Statistics --> Resolved Addresses**_ puedes encontrar varias **informaciones** que fueron "**resolved**" por wireshark como puerto/transporte a protocolo, MAC al fabricante, etc. Es interesante saber qué está implicado en la comunicación.

![](<../../../images/image (893).png>)

**Protocol Hierarchy**

En _**Statistics --> Protocol Hierarchy**_ puedes encontrar los **protocolos** **implicados** en la comunicación y datos sobre ellos.

![](<../../../images/image (586).png>)

**Conversations**

En _**Statistics --> Conversations**_ puedes encontrar un **resumen de las conversaciones** en la comunicación y datos sobre ellas.

![](<../../../images/image (453).png>)

**Endpoints**

En _**Statistics --> Endpoints**_ puedes encontrar un **resumen de los endpoints** en la comunicación y datos sobre cada uno de ellos.

![](<../../../images/image (896).png>)

**DNS info**

En _**Statistics --> DNS**_ puedes encontrar estadísticas sobre la solicitud DNS capturada.

![](<../../../images/image (1063).png>)

**I/O Graph**

En _**Statistics --> I/O Graph**_ puedes encontrar un **gráfico de la comunicación.**

![](<../../../images/image (992).png>)

### Filters

Aquí puedes encontrar filtros de wireshark según el protocolo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
En la versión actual de Wireshark usa `tls.*` en lugar de los antiguos nombres de filtro `ssl.*`.\
Otros filtros interesantes:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivot on the SNI sent in the ClientHello even when you cannot decrypt the payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Split classic HTTPS, HTTP/2 and HTTP/3 capable sessions quickly
- `quic or http3`
- Find modern UDP/443 traffic that will be missed if you only review TCP conversations

### Search

Si quieres **buscar** **contenido** dentro de los **paquetes** de las sesiones, pulsa _CTRL+f_. Puedes añadir nuevas capas a la barra principal de información (No., Time, Source, etc.) pulsando el botón derecho y luego edit column.

### Following multiplexed streams

Las versiones recientes de Wireshark pueden seguir directamente streams de `TLS`, `HTTP/2` y `QUIC`. En capturas ruidosas esto suele ser más rápido que usar solo `Follow TCP Stream`, especialmente cuando varias requests comparten la misma conexión.

### Free pcap labs

**Practice with the free challenges of:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

Puedes añadir una columna que muestre el encabezado Host HTTP:

![](<../../../images/image (639).png>)

Y una columna que añada el nombre del Server desde una conexión HTTPS iniciada (**tls.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

Si la captura está mayormente cifrada, añadir estos campos como columnas acelerará mucho el triage:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Esto permite agrupar sesiones por hostname, ALPN (`http/1.1`, `h2`, `h3`, etc.) y fingerprint del cliente incluso cuando el payload sigue cifrado. Para capturas HTTP/2 y HTTP/3 descifradas, también es útil añadir `http2.header.value` o `http3.headers.header.value` como columnas y pivotar sobre paths, authorities y otros metadatos interesantes.
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identifying local hostnames

### From DHCP

En Wireshark actual, en lugar de `bootp` necesitas buscar `DHCP`

![](<../../../images/image (1013).png>)

### From NBNS

![](<../../../images/image (1003).png>)

## Decrypting TLS

### Decrypting https traffic with server private key

_edit > preferences > protocols > tls >_

![](<../../../images/image (1103).png>)

Pulsa _Edit_ y añade todos los datos del server y la private key (_IP, Port, Protocol, Key file and password_)

Este método solo funciona en un número limitado de casos. Para tráfico TLS 1.3 / ECDHE actual, el método de session key log de abajo suele ser la opción práctica.

### Decrypting https traffic with symmetric session keys

Tanto Firefox como Chrome tienen la capacidad de registrar TLS session keys, que pueden usarse con Wireshark para decrypt TLS traffic. Esto permite un análisis profundo de las secure communications. Puedes encontrar más detalles sobre cómo realizar este decryption en una guía en [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/). Esta también es la ruta normal para decrypt modern TLS 1.3 y capturas QUIC/HTTP/3.

Para detectarlo, busca dentro del environment la variable `SSLKEYLOGFILE`

Un archivo de shared keys se verá así:

![](<../../../images/image (820).png>)

Si la captura es `pcapng`, comprueba si ya contiene embedded decryption secrets antes de revisar el host filesystem:
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Para importarlo en wireshark ve a \_edit > preferences > protocols > tls > e impórtalo en (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

## ADB communication

Extrae un APK de una comunicación ADB donde se envió el APK:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
## Referencias

- [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [Decrypting and parsing HTTP/3 traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
