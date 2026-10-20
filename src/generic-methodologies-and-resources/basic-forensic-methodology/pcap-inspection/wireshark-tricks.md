# Trucos de Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Mejora tus habilidades con Wireshark

### Tutoriales

Los siguientes tutoriales son excelentes para aprender algunos trucos básicos:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Información analizada

**Información experta**

Al hacer clic en _**Analizar** --> **Información experta**_, obtendrás una **descripción general** de lo que ocurre en los paquetes **analizados**:

![Tutoriales - Información analizada: Al hacer clic en Analizar -- Información experta, obtendrás una descripción general de lo que ocurre en los paquetes analizados](<../../../images/image (256).png>)

**Direcciones resueltas**

En _**Estadísticas --> Direcciones resueltas**_ encontrarás varios **datos** que Wireshark ha "**resuelto**", como el puerto/transporte a protocolo, la MAC al fabricante, etc. Es útil saber qué elementos intervienen en la comunicación.

![Tutoriales - Información analizada: En Estadísticas -- Direcciones resueltas encontrarás varios datos que Wireshark ha " resuelto " , como el puerto/transporte a protocolo, la MAC al...](<../../../images/image (893).png>)

**Jerarquía de protocolos**

En _**Estadísticas --> Jerarquía de protocolos**_ encontrarás los **protocolos** **involucrados** en la comunicación y datos sobre ellos.

![Tutoriales - Información analizada: En Estadísticas -- Jerarquía de protocolos encontrarás los protocolos involucrados en la comunicación y datos sobre ellos](<../../../images/image (586).png>)

**Conversaciones**

En _**Estadísticas --> Conversaciones**_ encontrarás un **resumen de las conversaciones** de la comunicación y datos sobre ellas.

![Tutoriales - Información analizada: En Estadísticas -- Conversaciones encontrarás un resumen de las conversaciones de la comunicación y datos sobre ellas](<../../../images/image (453).png>)

**Endpoints**

En _**Estadísticas --> Endpoints**_ encontrarás un **resumen de los endpoints** de la comunicación y datos sobre cada uno.

![Tutoriales - Información analizada: En Estadísticas -- Endpoints encontrarás un resumen de los endpoints de la comunicación y datos sobre cada uno](<../../../images/image (896).png>)

**Información de DNS**

En _**Estadísticas --> DNS**_ encontrarás estadísticas sobre las solicitudes DNS capturadas.

![Tutoriales - Información analizada: En Estadísticas -- DNS encontrarás estadísticas sobre las solicitudes DNS capturadas](<../../../images/image (1063).png>)

**Gráfico de E/S**

En _**Estadísticas --> Gráfico de E/S**_ encontrarás un **gráfico de la comunicación.**

![Tutoriales - Información analizada: En Estadísticas -- Gráfico de E/S encontrarás un gráfico de la comunicación](<../../../images/image (992).png>)

### Filtros

Aquí encontrarás filtros de Wireshark según el protocolo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
En las versiones actuales de Wireshark, usa `tls.*` en lugar de los antiguos nombres de filtro `ssl.*`.<sup>[[1]](#references)</sup>\
Otros filtros interesantes:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - Tráfico HTTP y HTTPS inicial
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - Tráfico HTTP y HTTPS inicial + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - Tráfico HTTP y HTTPS inicial + TCP SYN + solicitudes DNS
- `tls.handshake.extensions_server_name contains "example.com"`
  - Usa como punto de partida el SNI enviado en el ClientHello, incluso si no puedes descifrar el payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - Separa rápidamente las sesiones HTTPS clásicas y las compatibles con HTTP/2 y HTTP/3
- `quic or http3`
  - Encuentra tráfico moderno UDP/443 que no aparecerá si solo revisas las conversaciones TCP

### Búsqueda

Si quieres **buscar** **contenido** dentro de los **paquetes** de las sesiones, pulsa _CTRL+f_. Puedes añadir nuevas columnas a la barra de información principal (n.º, hora, origen, etc.) haciendo clic con el botón derecho y seleccionando la opción para editar columnas.

### Seguimiento de flujos multiplexados

Wireshark puede seguir directamente los flujos `TLS`, `HTTP/2` y `QUIC`. Sus cuadros de diálogo de HTTP/2 y QUIC muestran selectores de conexión y subflujo, lo que ayuda a aislar flujos multiplexados que comparten la misma conexión de nivel inferior.<sup>[[4]](#references)</sup>

Si tienes las claves de sesión, primero identifica el ID del flujo de la solicitud y luego sigue ese subflujo en lugar de toda la conversación TCP o UDP. El ejemplo `0,1` selecciona el ID de flujo HTTP/2 1 en el flujo TCP 0; para QUIC, usa `follow,quic,utf-8,<connection-number>,<stream-id>`. Seguir solo una tupla de cinco elementos puede mezclar solicitudes independientes o hacer que no encuentres una conexión QUIC tras una migración.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### Laboratorios gratuitos de pcap

**Practica con los desafíos gratuitos de:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identificación de dominios

Puedes añadir una columna que muestre el encabezado HTTP Host:

![Laboratorios gratuitos de pcap - Identificación de dominios: Puedes añadir una columna que muestre el encabezado HTTP Host](<../../../images/image (639).png>)

Y una columna que añada el nombre del servidor de una conexión HTTPS iniciada (**tls.handshake.type == 1**):

![Laboratorios gratuitos de pcap - Identificación de dominios: Y una columna que añada el nombre del servidor de una conexión HTTPS iniciada ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Si la captura está mayormente cifrada, añadir estos campos como columnas acelerará mucho la clasificación inicial:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Esto permite agrupar sesiones por nombre de host, ALPN (`http/1.1`, `h2`, `h3`, etc.) y huella digital del cliente, incluso cuando la carga útil sigue cifrada. Para capturas descifradas de HTTP/2 y HTTP/3, también resulta útil añadir `http2.header.value` o `http3.headers.header.value` como columnas y pivotar sobre rutas, autoridades y otros metadatos interesantes.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: no confundas el SNI externo con el origen

Encrypted ClientHello (ECH) puede colocar un nombre público de cobertura en el SNI externo visible mientras cifra el nombre interno. Por lo tanto, un inventario de dominios basado solo en SNI puede atribuir el tráfico ECH al origen equivocado. La extensión ECH por sí sola no demuestra que ECH haya funcionado: los clientes pueden enviar una extensión ECH GREASE. En Wireshark 4.2+, busca ofertas ECH externas con el siguiente filtro y considera el SNI indicado como un posible nombre de cobertura, no como el sitio solicitado.<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

Si tienes las claves de sesión del cliente correspondientes, inspecciona la autoridad/Host HTTP descifrada en lugar de inferir el origen a partir del SNI externo. Sin las claves, comprueba otras evidencias del origen capturadas, como DNS en texto claro, pero no equipares el SNI externo con el nombre oculto.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## Identificación de nombres de host locales

### Desde DHCP

En las versiones actuales de Wireshark, en lugar de `bootp`, debes buscar `DHCP`

![Identificación de nombres de host locales - Desde DHCP: En las versiones actuales de Wireshark, en lugar de bootp, debes buscar DHCP](<../../../images/image (1013).png>)

### Desde NBNS

![Desde DHCP - Desde NBNS: En las versiones actuales de Wireshark, en lugar de bootp, debes buscar DHCP](<../../../images/image (1003).png>)

## Descifrado de TLS

El descifrado de la capa de enlace Wi-Fi es independiente del descifrado de la sesión TLS; consulta [Wi-Fi PCAP analysis](wifi-pcap-analysis.md) para conocer los requisitos previos de claves y handshake.

### Descifrado del tráfico https con la clave privada del servidor

_edit > preferences > protocols > tls >_

![Descifrado de TLS - Descifrado del tráfico https con la clave privada del servidor: Descifrado del tráfico https con la clave privada del servidor](<../../../images/image (1103).png>)

Pulsa _Edit_ y añade todos los datos del servidor y la clave privada (_IP, Port, Protocol, Key file and password_)

Este método solo funciona en un número limitado de casos. Para el tráfico actual de TLS 1.3 / ECDHE, normalmente la opción práctica es el método de registro de claves de sesión que se indica a continuación.<sup>[[1]](#references)</sup>

### Descifrado del tráfico https con claves de sesión simétricas

Tanto Firefox como Chrome pueden registrar claves de sesión TLS, que se pueden usar con Wireshark para descifrar el tráfico TLS. Esto permite analizar en profundidad las comunicaciones seguras. Puedes encontrar más detalles sobre cómo realizar este descifrado en una guía de [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Esta también es la forma habitual de descifrar capturas modernas de TLS 1.3 y QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Para detectarlo, busca la variable `SSLKEYLOGFILE` en el entorno.

Un archivo de claves compartidas tendrá este aspecto:

![Descifrado del tráfico https con la clave privada del servidor - Descifrado del tráfico https con claves de sesión simétricas: Un archivo de claves compartidas tendrá este aspecto](<../../../images/image (820).png>)

Si la captura es `pcapng`, comprueba si ya contiene secretos de descifrado integrados antes de buscar en el sistema de archivos del host:<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

Para importarlo en Wireshark, ve a \_editar > preferencias > protocolos > tls > e impórtalo en el campo Nombre de archivo del registro de (Pre)-Master-Secret:

![Descifrado del tráfico https con la clave privada del servidor - Descifrado del tráfico https con claves de sesión simétricas: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## Comunicación ADB

Extrae un APK de una comunicación ADB en la que se haya enviado el APK:

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
- [4] [Seguimiento de flujos de protocolos](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Referencia de filtros de visualización: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Referencia de filtros de visualización: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Referencia de filtros de visualización: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [Manual de TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
