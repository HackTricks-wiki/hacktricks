# Trucos de Wireshark

## Mejora tus habilidades con Wireshark

### Tutoriales

Los siguientes tutoriales son increíbles para aprender algunos trucos básicos:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Información analizada

**Información experta**

Al hacer clic en _**Analyze** --> **Expert Information**_ tendrás una **visión general** de lo que ocurre en los paquetes **analizados**:

![Tutoriales - Información analizada: Al hacer clic en Analyze -- Expert Information tendrás una visión general de lo que ocurre en los paquetes analizados](<../../../images/image (256).png>)

**Direcciones resueltas**

En _**Statistics --> Resolved Addresses**_ puedes encontrar diversa **información** que fue "**resuelta**" por Wireshark, como puerto/transporte a protocolo, MAC al fabricante, etc. Es interesante saber qué elementos están implicados en la comunicación.

![Tutoriales - Información analizada: En Statistics -- Resolved Addresses puedes encontrar diversa información que fue " resuelta " por Wireshark, como puerto/transporte a protocolo, MAC al fabricante, etc.](<../../../images/image (893).png>)

**Jerarquía de protocolos**

En _**Statistics --> Protocol Hierarchy**_ puedes encontrar los **protocolos** **involucrados** en la comunicación y datos sobre ellos.

![Tutoriales - Información analizada: En Statistics -- Protocol Hierarchy puedes encontrar los protocolos involucrados en la comunicación y datos sobre ellos](<../../../images/image (586).png>)

**Conversaciones**

En _**Statistics --> Conversations**_ puedes encontrar un **resumen de las conversaciones** de la comunicación y datos sobre ellas.

![Tutoriales - Información analizada: En Statistics -- Conversations puedes encontrar un resumen de las conversaciones de la comunicación y datos sobre ellas](<../../../images/image (453).png>)

**Endpoints**

En _**Statistics --> Endpoints**_ puedes encontrar un **resumen de los endpoints** de la comunicación y datos sobre cada uno de ellos.

![Tutoriales - Información analizada: En Statistics -- Endpoints puedes encontrar un resumen de los endpoints de la comunicación y datos sobre cada uno de ellos](<../../../images/image (896).png>)

**Información de DNS**

En _**Statistics --> DNS**_ puedes encontrar estadísticas sobre la solicitud DNS capturada.

![Tutoriales - Información analizada: En Statistics -- DNS puedes encontrar estadísticas sobre la solicitud DNS capturada](<../../../images/image (1063).png>)

**Gráfico de I/O**

En _**Statistics --> I/O Graph**_ puedes encontrar un **gráfico de la comunicación.**

![Tutoriales - Información analizada: En Statistics -- I/O Graph puedes encontrar un gráfico de la comunicación](<../../../images/image (992).png>)

### Filtros

Aquí puedes encontrar filtros de Wireshark según el protocolo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
En el Wireshark actual, usa `tls.*` en lugar de los nombres antiguos de filtros `ssl.*`.<sup>[[1]](#references)</sup>\
Otros filtros interesantes:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- Tráfico HTTP y HTTPS inicial
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Tráfico HTTP y HTTPS inicial + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Tráfico HTTP y HTTPS inicial + TCP SYN + solicitudes DNS
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivotar sobre el SNI enviado en el ClientHello incluso cuando no puedas descifrar el payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Separar rápidamente las sesiones clásicas compatibles con HTTPS, HTTP/2 y HTTP/3
- `quic or http3`
- Encontrar tráfico UDP/443 moderno que se omitirá si solo revisas las conversaciones TCP

### Búsqueda

Si quieres **buscar** **contenido** dentro de los **paquetes** de las sesiones, pulsa _CTRL+f_. Puedes añadir nuevas capas a la barra principal de información (No., Time, Source, etc.) pulsando el botón derecho y seleccionando después la columna de edición.

### Seguir streams multiplexados

Wireshark puede seguir directamente streams `TLS`, `HTTP/2` y `QUIC`. Sus diálogos de HTTP/2 y QUIC muestran selectores de conexión y substream, lo que ayuda a aislar streams multiplexados que comparten la misma conexión de nivel inferior.<sup>[[4]](#references)</sup>

### Labs gratuitos de pcap

**Practica con los challenges gratuitos de:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identificación de dominios

Puedes añadir una columna que muestre el encabezado HTTP Host:

![Labs gratuitos de pcap - Identificación de dominios: Puedes añadir una columna que muestre el encabezado HTTP Host](<../../../images/image (639).png>)

Y una columna que añada el nombre del Server de una conexión HTTPS iniciada (**tls.handshake.type == 1**):

![Labs gratuitos de pcap - Identificación de dominios: Y una columna que añada el nombre del Server de una conexión HTTPS iniciada ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Si la captura está cifrada principalmente, añadir estos campos como columnas acelerará mucho la clasificación inicial:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Esto te permite agrupar sesiones por hostname, ALPN (`http/1.1`, `h2`, `h3`, etc.) y fingerprint del cliente incluso cuando el payload permanezca cifrado. Para capturas HTTP/2 y HTTP/3 descifradas, también es útil añadir `http2.header.value` o `http3.headers.header.value` como columnas y hacer Pivot sobre paths, authorities y otros metadatos interesantes.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identifying local hostnames

### From DHCP

In current Wireshark, instead of `bootp`, you need to search for `DHCP`

![Identifying local hostnames - From DHCP: En el Wireshark actual, en lugar de bootp, debes buscar DHCP](<../../../images/image (1013).png>)

### From NBNS

![From DHCP - From NBNS: En el Wireshark actual, en lugar de bootp, debes buscar DHCP](<../../../images/image (1003).png>)

## Descifrado de TLS

### Descifrado del tráfico https con la clave privada del servidor

_edit > preferences > protocols > tls >_

![Descifrado de TLS - Descifrado del tráfico https con la clave privada del servidor: Descifrado del tráfico https con la clave privada del servidor](<../../../images/image (1103).png>)

Presiona _Edit_ y añade todos los datos del servidor y la clave privada (_IP, Port, Protocol, Key file y password_)

Este método solo funciona en un número limitado de casos. Para el tráfico TLS 1.3 / ECDHE actual, el método de registro de claves de sesión que se muestra a continuación suele ser la opción práctica.<sup>[[1]](#references)</sup>

### Descifrado del tráfico https con claves de sesión simétricas

Tanto Firefox como Chrome tienen la capacidad de registrar las claves de sesión TLS, que pueden utilizarse con Wireshark para descifrar el tráfico TLS. Esto permite realizar un análisis detallado de las comunicaciones seguras. Puedes encontrar más detalles sobre cómo realizar este descifrado en una guía de [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Esta también es la vía normal para descifrar capturas modernas de TLS 1.3 y QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Para detectarlo, busca dentro del entorno la variable `SSLKEYLOGFILE`

Un archivo de claves compartidas tendrá este aspecto:

![Descifrado del tráfico https con la clave privada del servidor - Descifrado del tráfico https con claves de sesión simétricas: Un archivo de claves compartidas tendrá este aspecto](<../../../images/image (820).png>)

Si la captura es `pcapng`, comprueba si ya contiene secretos de descifrado integrados antes de buscar en el sistema de archivos del host:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Para importarlo en wireshark, ve a \_edit > preferences > protocols > tls > e impórtalo en (Pre)-Master-Secret log filename:

![Descifrado del tráfico https con la clave privada del servidor - Descifrado del tráfico https con claves de sesión simétricas: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## Comunicación ADB

Extrae un APK de una comunicación ADB en la que se envió el APK:
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
## References

- [1] [Wiki de TLS de Wireshark](https://wiki.wireshark.org/TLS)
- [2] [Descifrado y análisis del tráfico HTTP/3 en Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Descifrado del tráfico TLS del navegador con Wireshark: ¡la forma fácil!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Seguir streams de protocolos](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Referencia de Display Filters: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Referencia de Display Filters: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Referencia de Display Filters: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
